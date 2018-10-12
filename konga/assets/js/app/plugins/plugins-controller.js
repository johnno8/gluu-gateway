(function () {
  'use strict';

  angular.module('frontend.plugins')
    .controller('PluginsController', [
      '_', '$scope', '$log', '$state', 'ApiService', 'PluginsService', 'MessageService',
      '$uibModal', 'DialogService', 'PluginModel', 'ListConfig', 'UserService',
      function controller(_, $scope, $log, $state, ApiService, PluginsService, MessageService,
                          $uibModal, DialogService, PluginModel, ListConfig, UserService) {

        PluginModel.setScope($scope, false, 'items', 'itemCount');
        $scope = angular.extend($scope, angular.copy(ListConfig.getConfig('plugin', PluginModel)));
        $scope.user = UserService.user();
        $scope.onEditPlugin = onEditPlugin;
        $scope.updatePlugin = updatePlugin;
        $scope.getContext = getContext;

        /**
         * ----------------------------------------------------------------------
         * Functions
         * ----------------------------------------------------------------------
         */

        function updatePlugin(plugin) {

          if (!$scope.user.hasPermission('plugins', 'update')) {

            MessageService.error("You don't have permissions to perform this action")
            return false;
          }

          PluginsService.update(plugin.id, {
            enabled: plugin.enabled
          })
            .then(function (res) {
              $log.debug("updatePlugin", res)
              // $scope.items.data[$scope.items.data.indexOf(plugin)] = res.data;

            }).catch(function (err) {
            $log.error("updatePlugin", err)
          })
        }


        function onEditPlugin(item) {
          if (item.name == "gluu-client-auth") {
            if (item.service_id) {
              return $state.go("services.oauth-plugin", {service_id: item.service_id});
            } else if (item.route_id) {
              return $state.go("routes.oauth-plugin", {route_id: item.route_id});
            } else if (item.api_id) {
              return $state.go("apis.oauth-plugin", {api_id: item.api_id});
            } else {
              return $state.go("plugins.oauth-plugin");
            }
          }

          if (item.name == "gluu-pep") {
            if (item.service_id) {
              return $state.go("services.uma-plugin", {service_id: item.service_id});
            } else if (item.route_id) {
              return $state.go("routes.uma-plugin", {route_id: item.route_id});
            } else if (item.api_id) {
              return $state.go("apis.uma-plugin", {api_id: item.api_id});
            } else {
              return $state.go("plugins.uma-plugin");
            }
          }

          if (!$scope.user.hasPermission('plugins', 'edit')) {
            return false;
          }

          $uibModal.open({
            animation: true,
            ariaLabelledBy: 'modal-title',
            ariaDescribedBy: 'modal-body',
            templateUrl: 'js/app/plugins/modals/edit-plugin-modal.html',
            size: 'lg',
            controller: 'EditPluginController',
            resolve: {
              _plugin: function () {
                return _.cloneDeep(item)
              },
              _schema: function () {
                return PluginsService.schema(item.name)
              }
            }
          });
        }

        function _fetchData() {

          $scope.loading = true;
          PluginModel.load({
            size: $scope.itemsFetchSize
          }).then(function (response) {
            $scope.items = response;
            $scope.loading = false;
          })
        }

        function getContext(plugin) {
          if (plugin.service_id) {
            return 'services'
          } else if (plugin.route_id) {
            return 'routes'
          } else if (plugin.api_id) {
            return 'apis'
          } else {
            return 'global'
          }
        }

        /**
         * ------------------------------------------------------------
         * Listeners
         * ------------------------------------------------------------
         */
        $scope.$on("plugin.added", function () {
          _fetchData()
        });

        $scope.$on("plugin.updated", function (ev, plugin) {
          _fetchData()
        });


        $scope.$on('user.node.updated', function (node) {
          _fetchData()
        });


        _fetchData();

      }
    ])
  ;
}());
