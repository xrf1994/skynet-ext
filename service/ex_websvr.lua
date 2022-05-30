-- web服务模板
-- auth:diandian
-- date:2017/6/26

local skynet = require 'skynet.manager'
local socket = require "skynet.socket"

local CMD = {}

function CMD.start(config)
    local host = config.host or "127.0.0.1"
    local port = config.port or 8080
    local agent_num = config.agent_num or 1
    local execute = config.execute
    local domains = config.domains

    local agents = {}
    for i = 1, agent_num do
        local svr = skynet.newservice("ex_websvr_agent")
        skynet.call(svr, "lua", "start", execute, domains)
        table.insert(agents, svr)
    end

    local web_order = 1
    local listen = socket.listen(host, port)
    socket.start(listen, function(fd, addr)
        local svr = agents[web_order]
        skynet.send(svr, "lua", "attach", fd, addr)
        web_order = web_order + 1
        if web_order > #agents then
            web_order = 1
        end
    end)

    skynet.error("websvr:", config.name, host, port, agent_num, execute)
end

skynet.start(function()
    skynet.dispatch("lua", function(session, source, cmd, ...)
        return skynet.retpack(CMD[cmd](...))
    end)
end)
