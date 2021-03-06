package = "gluu-oauth-pep"
version = "1.0-0"
source = {
  url = "https://ox.gluu.org/luarocks/gluu-oauth-pep.1.0-0.zip"
}
description = {
  summary = "Gluu OAuth 2.0 client authentication",
  detailed = [[
    Kong plugin that allows you to protect your API (which is proxied by Kong) with the Gluu OAuth 2.0 back channel client authentication.
  ]],
  homepage = "https://github.com/GluuFederation/gluu-gateway/tree/master/kong/plugins/gluu-oauth-pep",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.gluu-oauth-pep.access"] = "access.lua",
    ["kong.plugins.gluu-oauth-pep.handler"] = "handler.lua",
    ["kong.plugins.gluu-oauth-pep.helper"] = "helper.lua",
    ["kong.plugins.gluu-oauth-pep.schema"] = "schema.lua"
  }
}
