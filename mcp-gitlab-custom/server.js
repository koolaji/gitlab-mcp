const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Gitlab } = require('@gitbeaker/rest');
const simpleGit = require('simple-git');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');

class MCPGitLabServer {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 3333;
    this.host = process.env.HOST || '0.0.0.0'; // Listen on all interfaces instead of just localhost
    this.gitlabUrl = process.env.GITLAB_URL || 'https://git.snpb.app';
    this.gitlabToken = process.env.GITLAB_TOKEN;
    this.gitReposPath = process.env.GIT_REPOS_PATH || '/git-repos';
    this.serverUrl = process.env.SERVER_URL || `http://mcp-gitlab-server:${this.port}`; // Use container name
    
    // Initialize GitLab client
    if (this.gitlabToken) {
      this.gitlab = new Gitlab({
        host: this.gitlabUrl,
        token: this.gitlabToken,
      });
      this.gitlabConnected = true;
    } else {
      this.gitlabConnected = false;
    }

    // Setup logger
    this.setupLogger();
    
    // Setup middleware and routes
    this.setupMiddleware();
    this.setupRoutes();
    
    // Ensure repos directory exists
    this.ensureReposDirectory();
  }

  setupLogger() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
          return `${timestamp} ${level}: ${message}`;
        })
      ),
      transports: [
        new winston.transports.Console(),
      ],
    });
  }

  setupMiddleware() {
    // Enable CORS with specific configuration for OpenWebUI
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS || '*',
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization']
    }));
    
    // Security middleware
    this.app.use(helmet({
      // Allow iframe embedding if needed by OpenWebUI
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          "frame-ancestors": ["'self'", process.env.ALLOWED_FRAME_ANCESTORS || '*']
        }
      }
    }));
    
    // Request parsing
    this.app.use(express.json());
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
    });
    this.app.use(limiter);
    
    // Logging middleware
    this.app.use((req, res, next) => {
      this.logger.info(`${req.method} ${req.path}`);
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', this.handleHealthCheck.bind(this));
    
    // MCP specific routes
    this.app.get('/mcp/repositories', this.handleListRepositories.bind(this));
    
    // GitLab specific routes
    this.app.get('/mcp/gitlab/projects', this.handleListProjects.bind(this));
    
    // Git operations
    this.app.post('/mcp/git/clone', this.handleCloneRepository.bind(this));
    this.app.post('/mcp/git/pull/:name', this.handlePullRepository.bind(this));
    this.app.get('/mcp/git/status/:name', this.handleRepositoryStatus.bind(this));
    this.app.get('/mcp/git/files/:name', this.handleListFiles.bind(this));
    this.app.get('/mcp/git/file/:name/*', this.handleGetFile.bind(this));
    
    // OpenAPI documentation
    this.app.get('/openapi.json', this.handleOpenAPI.bind(this));
    
    // Default route
    this.app.get('/', (req, res) => {
      res.send('MCP GitLab Server');
    });
  }

  async ensureReposDirectory() {
    try {
      await fs.mkdir(this.gitReposPath, { recursive: true });
      
      // Configure Git to skip SSH host key verification
      const git = simpleGit();
      await git.addConfig('core.sshCommand', 'ssh -o StrictHostKeyChecking=no');
      
      this.logger.info(`Repos directory ensured: ${this.gitReposPath}`);
    } catch (error) {
      this.logger.error('Failed to create repos directory:', error);
    }
  }

  start() {
    this.app.listen(this.port, this.host, () => {
      this.logger.info(`Server running on ${this.host}:${this.port}`);
      this.logger.info(`Using GitLab URL: ${this.gitlabUrl}`);
      this.logger.info(`OpenAPI specification available at: ${this.serverUrl}/openapi.json`);
    });
  }

  // Route handlers

  handleHealthCheck(req, res) {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      gitlabConnected: this.gitlabConnected,
      gitlabUrl: this.gitlabUrl,
      reposPath: this.gitReposPath,
      serverUrl: this.serverUrl,
      version: '1.0.0',
    });
  }

  async handleListRepositories(req, res) {
    try {
      const dirs = await fs.readdir(this.gitReposPath);
      
      const repos = [];
      for (const dir of dirs) {
        const repoPath = path.join(this.gitReposPath, dir);
        const stat = await fs.stat(repoPath);
        
        if (stat.isDirectory()) {
          try {
            const git = simpleGit(repoPath);
            const remotes = await git.getRemotes(true);
            const status = await git.status();
            
            repos.push({
              name: dir,
              path: repoPath,
              url: remotes.length > 0 ? remotes[0].refs.fetch : null,
              branch: status.current,
              modified: status.modified.length > 0,
            });
          } catch (error) {
            // Not a git repository, skip
          }
        }
      }
      
      res.json({ success: true, data: repos });
    } catch (error) {
      this.logger.error('Error listing repositories:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleListProjects(req, res) {
    try {
      if (!this.gitlab) {
        return res.status(400).json({
          success: false,
          error: 'GitLab client not initialized. Check your token configuration.'
        });
      }
      
      const projects = await this.gitlab.Projects.all();
      res.json({ success: true, data: projects });
    } catch (error) {
      this.logger.error('Error listing GitLab projects:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleCloneRepository(req, res) {
    try {
      const { url, name, branch = 'main' } = req.body;
      
      if (!url || !name) {
        return res.status(400).json({
          success: false,
          error: 'Missing required parameters: url and name'
        });
      }

      const repoPath = path.join(this.gitReposPath, name);
      
      // Check if directory already exists
      try {
        await fs.access(repoPath);
        return res.status(409).json({
          success: false,
          error: 'Repository already exists',
          message: `Directory ${name} already exists`
        });
      } catch (error) {
        // Directory doesn't exist, which is what we want
      }

      // Add authentication to HTTP URLs if needed
      let cloneUrl = url;
      if (cloneUrl.startsWith('http') && !cloneUrl.includes('@') && this.gitlabToken) {
        const urlObj = new URL(cloneUrl);
        cloneUrl = `https://oauth2:${this.gitlabToken}@${urlObj.host}${urlObj.pathname}`;
        this.logger.info(`Adding authentication to URL for ${name}`);
      }

      const git = simpleGit();
      let actualBranch = branch;
      
      // Try with specific branch first, fall back to default if needed
      try {
        // Try with specified branch
        await git.clone(cloneUrl, repoPath, ['--branch', branch]);
        this.logger.info(`Repository cloned with branch ${branch}: ${cloneUrl} -> ${repoPath}`);
      } catch (branchError) {
        // If branch doesn't exist, try default branch
        if (branchError.message.includes('Remote branch') && 
            branchError.message.includes('not found')) {
          this.logger.info(`Branch ${branch} not found, trying default branch`);
          
          // Clean up failed clone attempt if it exists
          try {
            await fs.rm(repoPath, { recursive: true, force: true });
          } catch (rmError) {
            // Ignore errors if directory doesn't exist
          }
          
          // Clone with default branch
          await git.clone(cloneUrl, repoPath);
          
          // Get actual default branch name
          const localGit = simpleGit(repoPath);
          const branchInfo = await localGit.branch();
          actualBranch = branchInfo.current;
          
          this.logger.info(`Repository cloned with default branch ${actualBranch}: ${cloneUrl} -> ${repoPath}`);
        } else {
          // If it's another error, re-throw it
          throw branchError;
        }
      }
      
      res.json({
        success: true,
        data: {
          name,
          path: repoPath,
          url,
          branch: actualBranch,
          // Add note if we used a different branch than requested
          ...(actualBranch !== branch ? {
            note: `Requested branch '${branch}' not found, used default branch '${actualBranch}' instead`
          } : {})
        }
      });
    } catch (error) {
      this.logger.error('Error cloning repository:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handlePullRepository(req, res) {
    try {
      const { name } = req.params;
      
      if (!name) {
        return res.status(400).json({
          success: false,
          error: 'Missing required parameter: name'
        });
      }
      
      const repoPath = path.join(this.gitReposPath, name);
      
      try {
        await fs.access(repoPath);
      } catch (error) {
        return res.status(404).json({
          success: false,
          error: 'Repository not found',
          message: `Directory ${name} does not exist`
        });
      }
      
      const git = simpleGit(repoPath);
      const pullResult = await git.pull();
      
      this.logger.info(`Repository pulled: ${name}`);
      
      res.json({
        success: true,
        data: {
          name,
          path: repoPath,
          result: pullResult
        }
      });
    } catch (error) {
      this.logger.error('Error pulling repository:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleRepositoryStatus(req, res) {
    try {
      const { name } = req.params;
      
      if (!name) {
        return res.status(400).json({
          success: false,
          error: 'Missing required parameter: name'
        });
      }
      
      const repoPath = path.join(this.gitReposPath, name);
      
      try {
        await fs.access(repoPath);
      } catch (error) {
        return res.status(404).json({
          success: false,
          error: 'Repository not found',
          message: `Directory ${name} does not exist`
        });
      }
      
      const git = simpleGit(repoPath);
      const status = await git.status();
      
      res.json({
        success: true,
        data: {
          name,
          path: repoPath,
          status
        }
      });
    } catch (error) {
      this.logger.error('Error getting repository status:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleListFiles(req, res) {
    try {
      const { name } = req.params;
      
      if (!name) {
        return res.status(400).json({
          success: false,
          error: 'Missing required parameter: name'
        });
      }
      
      const repoPath = path.join(this.gitReposPath, name);
      
      try {
        await fs.access(repoPath);
      } catch (error) {
        return res.status(404).json({
          success: false,
          error: 'Repository not found',
          message: `Directory ${name} does not exist`
        });
      }
      
      const readDirRecursive = async (dir, rootDir = '') => {
        const files = await fs.readdir(dir);
        const result = [];
        
        for (const file of files) {
          if (file === '.git') continue;
          
          const filePath = path.join(dir, file);
          const relativePath = path.join(rootDir, file);
          const stat = await fs.stat(filePath);
          
          if (stat.isDirectory()) {
            const subFiles = await readDirRecursive(filePath, relativePath);
            result.push(...subFiles);
          } else {
            result.push(relativePath);
          }
        }
        
        return result;
      };
      
      const files = await readDirRecursive(repoPath);
      
      res.json({
        success: true,
        data: {
          name,
          path: repoPath,
          files
        }
      });
    } catch (error) {
      this.logger.error('Error listing files:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleGetFile(req, res) {
    try {
      const { name } = req.params;
      const filePath = req.params[0];
      
      if (!name || !filePath) {
        return res.status(400).json({
          success: false,
          error: 'Missing required parameters: name and file path'
        });
      }
      
      const repoPath = path.join(this.gitReposPath, name);
      const fullPath = path.join(repoPath, filePath);
      
      try {
        await fs.access(fullPath);
      } catch (error) {
        return res.status(404).json({
          success: false,
          error: 'File not found',
          message: `File ${filePath} does not exist in repository ${name}`
        });
      }
      
      const content = await fs.readFile(fullPath, 'utf8');
      
      res.json({
        success: true,
        data: {
          name,
          path: fullPath,
          content
        }
      });
    } catch (error) {
      this.logger.error('Error getting file:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  handleOpenAPI(req, res) {
    const openapi = {
      openapi: '3.0.0',
      info: {
        title: 'MCP GitLab API',
        version: '1.0.0',
        description: 'API for MCP GitLab Server - Manage GitLab repositories and files from git.snpb.app',
        contact: {
          name: 'API Support',
          url: 'https://github.com/yourusername/mcp-gitlab-custom',
          email: 'support@example.com'
        },
        license: {
          name: 'MIT',
          url: 'https://opensource.org/licenses/MIT'
        }
      },
      servers: [
        {
          url: this.serverUrl,
          description: 'MCP GitLab Server'
        }
      ],
      components: {
        schemas: {
          HealthResponse: {
            type: 'object',
            properties: {
              status: { type: 'string', example: 'healthy' },
              timestamp: { type: 'string', format: 'date-time' },
              gitlabConnected: { type: 'boolean' },
              gitlabUrl: { type: 'string', example: 'https://git.snpb.app' },
              reposPath: { type: 'string' },
              serverUrl: { type: 'string', example: 'http://mcp-gitlab-server:3333' },
              version: { type: 'string' }
            }
          },
          ErrorResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: false },
              error: { type: 'string' },
              message: { type: 'string' }
            }
          },
          RepositoryInfo: {
            type: 'object',
            properties: {
              name: { type: 'string', example: 'my-repo' },
              path: { type: 'string', example: '/git-repos/my-repo' },
              url: { type: 'string', example: 'https://git.snpb.app/user/my-repo.git' },
              branch: { type: 'string', example: 'main' },
              modified: { type: 'boolean', example: false }
            }
          },
          RepositoriesList: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'array',
                items: { $ref: '#/components/schemas/RepositoryInfo' }
              }
            }
          },
          ProjectsList: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'integer', example: 123 },
                    name: { type: 'string', example: 'Project Name' },
                    description: { type: 'string', example: 'Project description' },
                    web_url: { type: 'string', example: 'https://git.snpb.app/user/project' },
                    http_url_to_repo: { type: 'string', example: 'https://git.snpb.app/user/project.git' }
                  }
                }
              }
            }
          },
          CloneRequest: {
            type: 'object',
            required: ['url', 'name'],
            properties: {
              url: {
                type: 'string',
                description: 'Repository URL',
                example: 'https://git.snpb.app/user/repo.git'
              },
              name: {
                type: 'string',
                description: 'Repository name',
                example: 'my-repo'
              },
              branch: {
                type: 'string',
                description: 'Branch to clone',
                example: 'main'
              }
            }
          },
          CloneResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'my-repo' },
                  path: { type: 'string', example: '/git-repos/my-repo' },
                  url: { type: 'string', example: 'https://git.snpb.app/user/repo.git' },
                  branch: { type: 'string', example: 'main' },
                  note: { type: 'string', example: "Requested branch 'feature' not found, used default branch 'main' instead" }
                }
              }
            }
          },
          PullResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'my-repo' },
                  path: { type: 'string', example: '/git-repos/my-repo' },
                  result: { type: 'object' }
                }
              }
            }
          },
          StatusResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'my-repo' },
                  path: { type: 'string', example: '/git-repos/my-repo' },
                  status: { type: 'object' }
                }
              }
            }
          },
          FilesList: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'my-repo' },
                  path: { type: 'string', example: '/git-repos/my-repo' },
                  files: {
                    type: 'array',
                    items: { type: 'string' }
                  }
                }
              }
            }
          },
          FileContent: {
            type: 'object',
            properties: {
              success: { type: 'boolean', example: true },
              data: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'my-repo' },
                  path: { type: 'string', example: '/git-repos/my-repo/file.txt' },
                  content: { type: 'string', example: 'File content here...' }
                }
              }
            }
          }
        },
        securitySchemes: {
          gitlabToken: {
            type: 'apiKey',
            in: 'header',
            name: 'X-GitLab-Token',
            description: 'GitLab API token for authentication'
          }
        }
      },
      paths: {
        '/health': {
          get: {
            operationId: 'getHealth',
            tags: ['System'],
            summary: 'Get server health status',
            description: 'Returns the health status of the server, including GitLab connection status',
            responses: {
              '200': {
                description: 'Server health status',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/HealthResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/repositories': {
          get: {
            operationId: 'listRepositories',
            tags: ['Repositories'],
            summary: 'List all repositories',
            description: 'Returns a list of all repositories in the git repos directory',
            responses: {
              '200': {
                description: 'List of repositories',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/RepositoriesList' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/gitlab/projects': {
          get: {
            operationId: 'listProjects',
            tags: ['GitLab'],
            summary: 'List all GitLab projects',
            description: 'Returns a list of all GitLab projects accessible with the configured token from git.snpb.app',
            security: [{ gitlabToken: [] }],
            responses: {
              '200': {
                description: 'List of GitLab projects',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ProjectsList' }
                  }
                }
              },
              '400': {
                description: 'GitLab client not initialized',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/git/clone': {
          post: {
            operationId: 'cloneRepository',
            tags: ['Git'],
            summary: 'Clone a repository',
            description: 'Clones a Git repository into the git repos directory',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/CloneRequest' }
                }
              }
            },
            responses: {
              '200': {
                description: 'Repository cloned successfully',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/CloneResponse' }
                  }
                }
              },
              '400': {
                description: 'Bad request - missing required parameters',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '409': {
                description: 'Repository already exists',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/git/pull/{name}': {
          post: {
            operationId: 'pullRepository',
            tags: ['Git'],
            summary: 'Pull latest changes for a repository',
            description: 'Pulls the latest changes for a repository from its remote',
            parameters: [
              {
                name: 'name',
                in: 'path',
                required: true,
                schema: { type: 'string' },
                description: 'Repository name'
              }
            ],
            responses: {
              '200': {
                description: 'Repository pulled successfully',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/PullResponse' }
                  }
                }
              },
              '400': {
                description: 'Bad request - missing required parameter',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '404': {
                description: 'Repository not found',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/git/status/{name}': {
          get: {
            operationId: 'getRepositoryStatus',
            tags: ['Git'],
            summary: 'Get repository status',
            description: 'Returns the Git status of a repository',
            parameters: [
              {
                name: 'name',
                in: 'path',
                required: true,
                schema: { type: 'string' },
                description: 'Repository name'
              }
            ],
            responses: {
              '200': {
                description: 'Repository status',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/StatusResponse' }
                  }
                }
              },
              '400': {
                description: 'Bad request - missing required parameter',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '404': {
                description: 'Repository not found',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/git/files/{name}': {
          get: {
            operationId: 'listFiles',
            tags: ['Files'],
            summary: 'List files in a repository',
            description: 'Returns a list of all files in a repository',
            parameters: [
              {
                name: 'name',
                in: 'path',
                required: true,
                schema: { type: 'string' },
                description: 'Repository name'
              }
            ],
            responses: {
              '200': {
                description: 'List of files',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/FilesList' }
                  }
                }
              },
              '400': {
                description: 'Bad request - missing required parameter',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '404': {
                description: 'Repository not found',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        },
        '/mcp/git/file/{name}/{path}': {
          get: {
            operationId: 'getFile',
            tags: ['Files'],
            summary: 'Get file content',
            description: 'Returns the content of a file in a repository',
            parameters: [
              {
                name: 'name',
                in: 'path',
                required: true,
                schema: { type: 'string' },
                description: 'Repository name'
              },
              {
                name: 'path',
                in: 'path',
                required: true,
                schema: { type: 'string' },
                description: 'File path within the repository'
              }
            ],
            responses: {
              '200': {
                description: 'File content',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/FileContent' }
                  }
                }
              },
              '400': {
                description: 'Bad request - missing required parameters',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '404': {
                description: 'File not found',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              },
              '500': {
                description: 'Internal server error',
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/ErrorResponse' }
                  }
                }
              }
            }
          }
        }
      }
    };
    
    res.json(openapi);
  }
}

// Start the server
const server = new MCPGitLabServer();
server.start();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down gracefully...');
  process.exit(0);
});