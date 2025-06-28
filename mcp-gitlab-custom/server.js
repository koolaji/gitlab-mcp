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
    this.gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';
    this.gitlabToken = process.env.GITLAB_TOKEN;
    this.gitReposPath = process.env.GIT_REPOS_PATH || '/tmp/repos';
    
    // Initialize GitLab client
    if (this.gitlabToken) {
      this.gitlab = new Gitlab({
        host: this.gitlabUrl,
        token: this.gitlabToken,
      });
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
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'mcp-gitlab-server' },
      transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ],
    });
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet());
    
    // CORS configuration for Open WebUI
    this.app.use(cors({
      origin: [
        'http://localhost:3000', 
        'http://open-webui:8080',
        'http://localhost:8080',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:8080'
      ],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.'
    });
    this.app.use(limiter);
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request logging
    this.app.use((req, res, next) => {
      this.logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        gitlabConnected: !!this.gitlab,
        reposPath: this.gitReposPath,
        version: '1.0.0'
      });
    });

    // OpenAPI specification endpoint for Open WebUI
    this.app.get('/openapi.json', (req, res) => {
      const openApiSpec = {
        openapi: '3.0.0',
        info: {
          title: 'MCP GitLab Server API',
          version: '1.0.0',
          description: 'GitLab integration API for Open WebUI - Manage repositories, projects, and Git operations'
        },
        servers: [
          {
            url: `http://mcp-gitlab-server:3333`,
            description: 'MCP GitLab Server'
          }
        ],
        paths: {
          '/health': {
            get: {
              summary: 'Health check',
              description: 'Check server health and connection status',
              responses: {
                '200': {
                  description: 'Server health status',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          status: { type: 'string', example: 'healthy' },
                          timestamp: { type: 'string', format: 'date-time' },
                          gitlabConnected: { type: 'boolean' },
                          reposPath: { type: 'string' },
                          version: { type: 'string' }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/mcp/repositories': {
            get: {
              summary: 'List all local repositories',
              description: 'Get a list of all locally cloned repositories',
              responses: {
                '200': {
                  description: 'List of repositories',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          success: { type: 'boolean' },
                          data: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                name: { type: 'string' },
                                path: { type: 'string' },
                                branch: { type: 'string' },
                                isDirty: { type: 'boolean' },
                                lastCommit: { type: 'string' },
                                remoteUrl: { type: 'string' }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/mcp/gitlab/projects': {
            get: {
              summary: 'List GitLab projects',
              description: 'Get a list of all accessible GitLab projects',
              responses: {
                '200': {
                  description: 'List of GitLab projects',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          success: { type: 'boolean' },
                          data: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                id: { type: 'integer' },
                                name: { type: 'string' },
                                path: { type: 'string' },
                                url: { type: 'string' },
                                description: { type: 'string' },
                                defaultBranch: { type: 'string' },
                                visibility: { type: 'string' }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/mcp/git/clone': {
            post: {
              summary: 'Clone a repository',
              description: 'Clone a Git repository to local storage',
              requestBody: {
                required: true,
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        url: { 
                          type: 'string', 
                          description: 'Repository URL to clone',
                          example: 'https://git.snpb.app/username/repo.git'
                        },
                        name: { 
                          type: 'string', 
                          description: 'Local repository name',
                          example: 'my-project'
                        },
                        branch: { 
                          type: 'string', 
                          description: 'Branch to clone', 
                          default: 'main',
                          example: 'main'
                        }
                      },
                      required: ['url', 'name']
                    }
                  }
                }
              },
              responses: {
                '200': {
                  description: 'Repository cloned successfully',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          success: { type: 'boolean' },
                          data: {
                            type: 'object',
                            properties: {
                              name: { type: 'string' },
                              path: { type: 'string' },
                              url: { type: 'string' },
                              branch: { type: 'string' }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/mcp/git/status/{repoName}': {
            get: {
              summary: 'Get repository status',
              description: 'Get the Git status of a specific repository',
              parameters: [
                {
                  name: 'repoName',
                  in: 'path',
                  required: true,
                  schema: { type: 'string' },
                  description: 'Name of the repository'
                }
              ],
              responses: {
                '200': {
                  description: 'Repository status',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          success: { type: 'boolean' },
                          data: {
                            type: 'object',
                            properties: {
                              branch: { type: 'string' },
                              ahead: { type: 'integer' },
                              behind: { type: 'integer' },
                              staged: { type: 'array', items: { type: 'string' } },
                              modified: { type: 'array', items: { type: 'string' } },
                              untracked: { type: 'array', items: { type: 'string' } }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          '/mcp/git/pull/{repoName}': {
            post: {
              summary: 'Pull repository changes',
              description: 'Pull latest changes from remote repository',
              parameters: [
                {
                  name: 'repoName',
                  in: 'path',
                  required: true,
                  schema: { type: 'string' },
                  description: 'Name of the repository'
                }
              ],
              responses: {
                '200': {
                  description: 'Pull completed successfully',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          success: { type: 'boolean' },
                          data: {
                            type: 'object',
                            properties: {
                              summary: { type: 'string' },
                              files: { type: 'array', items: { type: 'string' } }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      };
      
      res.json(openApiSpec);
    });

    // MCP Capabilities endpoint
    this.app.get('/mcp/capabilities', (req, res) => {
      res.json({
        success: true,
        data: {
          tools: [
            'list_repositories',
            'list_gitlab_projects', 
            'clone_repository',
            'get_repository_status',
            'pull_repository',
            'get_file_content',
            'list_files'
          ],
          version: '1.0.0',
          description: 'MCP GitLab Server with Git operations'
        }
      });
    });

    // Repository management routes
    this.app.get('/mcp/repositories', this.handleListRepositories.bind(this));
    
    // GitLab routes
    this.app.get('/mcp/gitlab/projects', this.handleListGitLabProjects.bind(this));
    this.app.get('/mcp/gitlab/project/:id', this.handleGetGitLabProject.bind(this));
    
    // Git operation routes
    this.app.post('/mcp/git/clone', this.handleCloneRepository.bind(this));
    this.app.get('/mcp/git/status/:repoName', this.handleGetRepositoryStatus.bind(this));
    this.app.post('/mcp/git/pull/:repoName', this.handlePullRepository.bind(this));
    this.app.post('/mcp/git/push/:repoName', this.handlePushRepository.bind(this));
    this.app.get('/mcp/git/files/:repoName', this.handleListFiles.bind(this));
    this.app.get('/mcp/git/file/:repoName/*', this.handleGetFileContent.bind(this));

    // Error handling middleware
    this.app.use((err, req, res, next) => {
      this.logger.error('Unhandled error:', err);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: 'Not found',
        message: `Route ${req.method} ${req.originalUrl} not found`
      });
    });
  }

  async ensureReposDirectory() {
    try {
      await fs.mkdir(this.gitReposPath, { recursive: true });
      this.logger.info(`Repos directory ensured: ${this.gitReposPath}`);
    } catch (error) {
      this.logger.error('Failed to create repos directory:', error);
    }
  }

  // Route handlers
  async handleListRepositories(req, res) {
    try {
      const repos = [];
      const entries = await fs.readdir(this.gitReposPath, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const repoPath = path.join(this.gitReposPath, entry.name);
          const git = simpleGit(repoPath);
          
          try {
            const isRepo = await git.checkIsRepo();
            if (isRepo) {
              const status = await git.status();
              const remotes = await git.getRemotes(true);
              const log = await git.log({ maxCount: 1 });
              
              repos.push({
                name: entry.name,
                path: repoPath,
                branch: status.current,
                isDirty: !status.isClean(),
                lastCommit: log.latest ? log.latest.hash.substring(0, 8) : null,
                remoteUrl: remotes.length > 0 ? remotes[0].refs.fetch : null
              });
            }
          } catch (gitError) {
            this.logger.warn(`Error checking repo ${entry.name}:`, gitError.message);
          }
        }
      }
      
      res.json({ success: true, data: repos });
    } catch (error) {
      this.logger.error('Error listing repositories:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleListGitLabProjects(req, res) {
    try {
      if (!this.gitlab) {
        return res.status(400).json({
          success: false,
          error: 'GitLab not configured',
          message: 'GITLAB_TOKEN not provided'
        });
      }

      const projects = await this.gitlab.Projects.all({
        membership: true,
        perPage: 100
      });

      const formattedProjects = projects.map(project => ({
        id: project.id,
        name: project.name,
        path: project.path,
        url: project.web_url,
        sshUrl: project.ssh_url_to_repo,
        httpUrl: project.http_url_to_repo,
        description: project.description,
        defaultBranch: project.default_branch,
        visibility: project.visibility
      }));

      res.json({ success: true, data: formattedProjects });
    } catch (error) {
      this.logger.error('Error listing GitLab projects:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleGetGitLabProject(req, res) {
    try {
      if (!this.gitlab) {
        return res.status(400).json({
          success: false,
          error: 'GitLab not configured'
        });
      }

      const project = await this.gitlab.Projects.show(req.params.id);
      res.json({ success: true, data: project });
    } catch (error) {
      this.logger.error('Error getting GitLab project:', error);
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

      const git = simpleGit();
      await git.clone(url, repoPath, ['--branch', branch]);
      
      this.logger.info(`Repository cloned: ${url} -> ${repoPath}`);
      
      res.json({
        success: true,
        data: {
          name,
          path: repoPath,
          url,
          branch
        }
      });
    } catch (error) {
      this.logger.error('Error cloning repository:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleGetRepositoryStatus(req, res) {
    try {
      const { repoName } = req.params;
      const repoPath = path.join(this.gitReposPath, repoName);
      
      const git = simpleGit(repoPath);
      const status = await git.status();
      
      res.json({
        success: true,
        data: {
          branch: status.current,
          ahead: status.ahead,
          behind: status.behind,
          staged: status.staged,
          modified: status.modified,
          untracked: status.not_added
        }
      });
    } catch (error) {
      this.logger.error('Error getting repository status:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handlePullRepository(req, res) {
    try {
      const { repoName } = req.params;
      const repoPath = path.join(this.gitReposPath, repoName);
      
      const git = simpleGit(repoPath);
      const pullResult = await git.pull();
      
      res.json({
        success: true,
        data: {
          summary: pullResult.summary,
          files: pullResult.files || []
        }
      });
    } catch (error) {
      this.logger.error('Error pulling repository:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handlePushRepository(req, res) {
    try {
      const { repoName } = req.params;
      const repoPath = path.join(this.gitReposPath, repoName);
      
      const git = simpleGit(repoPath);
      const pushResult = await git.push();
      
      res.json({ success: true, data: pushResult });
    } catch (error) {
      this.logger.error('Error pushing repository:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleListFiles(req, res) {
    try {
      const { repoName } = req.params;
      const repoPath = path.join(this.gitReposPath, repoName);
      
      const files = await this.getDirectoryTree(repoPath);
      res.json({ success: true, data: files });
    } catch (error) {
      this.logger.error('Error listing files:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleGetFileContent(req, res) {
    try {
      const { repoName } = req.params;
      const filePath = req.params[0]; // Captures the rest of the path
      const fullPath = path.join(this.gitReposPath, repoName, filePath);
      
      // Security check - ensure path is within repo directory
      const resolvedPath = path.resolve(fullPath);
      const repoPath = path.resolve(path.join(this.gitReposPath, repoName));
      
      if (!resolvedPath.startsWith(repoPath)) {
        return res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'Path outside repository'
        });
      }
      
      const content = await fs.readFile(resolvedPath, 'utf8');
      res.json({
        success: true,
        data: {
          path: filePath,
          content: content
        }
      });
    } catch (error) {
      this.logger.error('Error getting file content:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async getDirectoryTree(dirPath, relativePath = '') {
    const items = [];
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      if (entry.name.startsWith('.git')) continue;
      
      const fullPath = path.join(dirPath, entry.name);
      const relPath = path.join(relativePath, entry.name);
      
      if (entry.isDirectory()) {
        const children = await this.getDirectoryTree(fullPath, relPath);
        items.push({
          name: entry.name,
          type: 'directory',
          path: relPath,
          children: children
        });
      } else {
        const stats = await fs.stat(fullPath);
        items.push({
          name: entry.name,
          type: 'file',
          path: relPath,
          size: stats.size,
          modified: stats.mtime
        });
      }
    }
    
    return items;
  }

  start() {
    this.app.listen(this.port, '0.0.0.0', () => {
      this.logger.info(`MCP GitLab Server running on port ${this.port}`);
      this.logger.info(`GitLab URL: ${this.gitlabUrl}`);
      this.logger.info(`GitLab Token: ${this.gitlabToken ? 'Configured' : 'Not configured'}`);
      this.logger.info(`Repos Path: ${this.gitReposPath}`);
      this.logger.info(`OpenAPI Spec available at: http://localhost:${this.port}/openapi.json`);
    });
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
