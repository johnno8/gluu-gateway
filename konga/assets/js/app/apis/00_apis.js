(function () {
  'use strict';

  angular.module('frontend.apis', [
    'angular.chips',
    'ngFileUpload'
  ]);

  // Module configuration
  angular.module('frontend.apis')
    .config([
      '$stateProvider',
      function config($stateProvider) {
        $stateProvider
          .state('apis', {
            parent: 'frontend',
            url: '/apis',
            data: {
              activeNode: true,
              pageName: "APIs",
              pageDescription: "The API object describes an API that's being exposed by Kong. Kong needs to know how to retrieve the API when a consumer is calling it from the Proxy port. Each API object must specify a request host, a request path or both. Kong will proxy all requests to the API to the specified upstream URL.",
              //displayName : "apis",
              prefix: '<i class="material-icons">cloud_queue</i>'
            },
            views: {
              'content@': {
                templateUrl: 'js/app/apis/views/apis.html',
                controller: 'ApisController',
              }
            }
          })
          .state('apis.edit', {
            url: '/:api_id/edit',
            data: {
              pageName: "Edit API",
              pageDescription: "",
              displayName: "edit API",
              prefix: '<i class="mdi mdi-pencil"></i>'
            },
            views: {
              'content@': {
                templateUrl: 'js/app/apis/views/edit-api.html',
                controller: 'ApiController',
                resolve: {
                  _api: [
                    'ApiService', '$stateParams',
                    function resolve(ApiService, $stateParams) {
                      return ApiService.findById($stateParams.api_id)
                    }
                  ],
                  _activeNode: [
                    'NodesService',
                    function resolve(NodesService) {
                      return NodesService.isActiveNodeSet()
                    }
                  ],
                }

              },
              'details@apis.edit': {
                templateUrl: 'js/app/apis/views/api-details.html',
                controller: 'ApiDetailsController',
              },
              'plugins@apis.edit': {
                templateUrl: 'js/app/apis/views/api-plugins.html',
                controller: 'ApiPluginsController',
                resolve: {
                  _plugins: [
                    'PluginsService', '$stateParams',
                    function (PluginsService, $stateParams) {
                      return PluginsService.load({api_id: $stateParams.api_id})
                    }
                  ]
                }
              },
              'healthchecks@apis.edit': {
                templateUrl: 'js/app/apis/views/api-health-checks.html',
                controller: 'ApiHealthChecksController',
              }
            }
          })
          .state('apis.oauth-plugin', {
            url: '/:api_id/oauth-plugin',
            data: {
              pageName: "Gluu Client Auth plugin",
              pageDescription: "This plugin enables the use of an external OpenID Provider for OAuth2 client registration and authentication. It needs to connect via `https` to Gluu's `oxd` service, which is an OAuth2 client middleware service.",
              displayName: "Gluu Client Auth plugin",
              prefix: '<i class="mdi mdi-pencil"></i>'
            },
            views: {
              'content@': {
                templateUrl: 'js/app/plugins/oauth-plugin.html',
                controller: 'OAuthPluginController',
                resolve: {
                  _context_name: [
                    '$log',
                    function resolve() {
                      return 'api';
                    }
                  ],
                  _context_data: [
                    '$stateParams',
                    'ApiService',
                    '$log',
                    function resolve($stateParams,
                                     ApiService) {
                      return ApiService.findById($stateParams.api_id)
                    }
                  ],
                  _plugins: [
                    'PluginsService', '$stateParams',
                    function resolve(PluginsService, $stateParams) {
                      return PluginsService.load({api_id: $stateParams.api_id})
                    }
                  ],
                  _activeNode: [
                    'NodesService',
                    function resolve(NodesService) {
                      return NodesService.isActiveNodeSet()
                    }
                  ],
                }
              }
            }
          })
          .state('apis.uma-plugin', {
            url: '/:api_id/uma-plugin',
            data: {
              pageName: "Gluu PEP plugin",
              pageDescription: "This plugin enables the use of an external OpenID Provider for UMA resource registration and authorization. It needs to connect to Gluu's `oxd` service, which is an OAuth2 client middleware service.",
              displayName: "Gluu PEP plugin",
              prefix: '<i class="mdi mdi-pencil"></i>'
            },
            views: {
              'content@': {
                templateUrl: 'js/app/plugins/uma-plugin.html',
                controller: 'UMAPluginController',
                resolve: {
                  _context_name: [
                    '$log',
                    function resolve() {
                      return 'api';
                    }
                  ],
                  _context_data: [
                    '$stateParams',
                    'ApiService',
                    '$log',
                    function resolve($stateParams,
                                     ApiService) {
                      return ApiService.findById($stateParams.api_id)
                    }
                  ],
                  _plugins: [
                    'PluginsService', '$stateParams',
                    function resolve(PluginsService, $stateParams) {
                      return PluginsService.load({api_id: $stateParams.api_id})
                    }
                  ],
                  _activeNode: [
                    'NodesService',
                    function resolve(NodesService) {
                      return NodesService.isActiveNodeSet()
                    }
                  ],
                }
              }
            }
          })
          .state('apis.plugins', {
            url: '/:api_id/plugins',
            params: {
              api: {}
            },
            data: {
              pageName: "API Plugins",
              displayName: "API plugins"
            },
            views: {
              'content@': {
                templateUrl: 'js/app/apis/views/api-plugins.html',
                controller: 'ApiPluginsController',
                resolve: {
                  _api: [
                    'ApiService', '$stateParams',
                    function (ApiService, $stateParams) {
                      return ApiService.findById($stateParams.api_id)
                    }
                  ],
                  _plugins: [
                    'PluginsService', '$stateParams',
                    function (PluginsService, $stateParams) {
                      return PluginsService.load({
                        api_id: $stateParams.api_id
                      })
                    }
                  ],
                  _activeNode: [
                    'NodesService',
                    function resolve(NodesService) {

                      return NodesService.isActiveNodeSet()
                    }
                  ],
                }
              }
            },
          })
          .state('apis.plugins.manage', {
            url: '/manage',
            data: {
              pageName: "Manage API Plugins",
              displayName: "manage"
            },
            views: {
              'content@': {
                templateUrl: 'js/app/apis/views/plugins/manage/manage-api-plugins.html',
                controller: 'ManageApiPluginsController',
                resolve: {
                  _api: [
                    '$stateParams',
                    'ApiService',
                    '$log',
                    function resolve($stateParams,
                                     ApiService,
                                     $log) {
                      return ApiService.findById($stateParams.api_id)
                    }
                  ],
                  _plugins: [
                    '$stateParams',
                    'ApiService',
                    '$log',
                    function resolve($stateParams,
                                     ApiService,
                                     $log) {
                      return ApiService.plugins($stateParams.api_id)
                    }
                  ],
                  _info: [
                    '$stateParams',
                    'InfoService',
                    '$log',
                    function resolve($stateParams,
                                     InfoService,
                                     $log) {
                      return InfoService.getInfo()
                    }
                  ],
                  _activeNode: [
                    'NodesService',
                    function resolve(NodesService) {

                      return NodesService.isActiveNodeSet()
                    }
                  ],
                }
              }
            },
          })
      }
    ])
  ;
}());
