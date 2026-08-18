--
-- The Kong entry point handler
--

local access = require "kong.plugins.sender-constrained.access"

-- See https://github.com/Kong/kong/discussions/7193 for more about the PRIORITY field
local SenderConstrained = {
    PRIORITY = 2000,
    VERSION = "1.1.0",
}

function SenderConstrained:access(conf)
    access.run(conf)
end

return SenderConstrained
