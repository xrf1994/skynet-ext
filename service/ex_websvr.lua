-- web服务模板
-- auth:diandian
-- date:2017/6/26

local skynet = require 'skynet.manager'
local socket = require "skynet.socket"
local ex_log = require "ex_log"

local M = {}

local host, port
local sname, agent_num, execute

function M.init(config)
    host = config.host or "127.0.0.1"
    port = config.port or 8080
    sname = config.name
    agent_num = config.agent_num or 1
    execute = config.execute
    local domains = config.domains
    local max_reader = tonumber(config.max_reader)

    local agents = {}
    for i = 1, agent_num do
        local svr = skynet.newservice("ex_websvr_agent")
        skynet.call(svr, "lua", "start", execute, domains, max_reader)
        table.insert(agents, svr)
    end

    return agents
end


function M.start(agents)
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
    skynet.error("websvr start:", sname, host, port, agent_num, execute)
end

return M
