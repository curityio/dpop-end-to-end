--
-- The Kong entry point handler
--

local access = require 'kong.plugins.dpop-sender-constrained.access'

-- See https://github.com/Kong/kong/discussions/7193 for more about the PRIORITY field
local DpopSenderConstrained = {
    PRIORITY = 999,
    VERSION = "1.1.0",
}

function DpopSenderConstrained:access(conf)
    access.run(conf)
end

return DpopSenderConstrained
