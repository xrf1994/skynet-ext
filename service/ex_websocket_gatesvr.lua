
local skynet = require "skynet"
local gateserver = require "wsgateserver"
local netpack = require "websocketnetpack"
local socketdriver = require "skynet.socketdriver"
local protobuf = require "protobuf"
local ex_log = require "ex_log"
local inspect = require "inspect"
local ex_cluster = require "ex_cluster"
local ex_utils = require "ex_utils"


local _fdmap = {}
local handler = {}

local handshake_fn
local on_message_fn
local pack_message_fn
local on_closefd_fn
local on_connect_fn
local on_open_fn

local function close_fd(fd)
    local c = _fdmap[fd]
    if not c then
        return
    end
    _fdmap[fd] = nil
    if on_closefd_fn then
        on_closefd_fn(c)
    end
end

function handler.message(fd, msg, sz)
    local c = _fdmap[fd]
    assert(c, fd)
    local data = netpack.tostring(msg, sz)
    if not c.handshake then
        local ret, is_shake, continue_msg = pcall(handshake_fn, c, data)
        if not ret then
            ex_log.error("handshake error:", is_shake)
            return close_fd(fd)
        end
        c.handshake = is_shake
        if is_shake and continue_msg then
            data = continue_msg
        else
            return
        end
    end
    if on_message_fn then
        on_message_fn(c, data)
    end
end

function handler.connect(fd, addr)
    ex_log.info("client connect:", fd, addr)
    local c = {
        fd = fd,
        addr = addr,
        ctime = os.time(),
        handshake = false,
        send = function(data)
            socketdriver.send(fd, netpack.pack(data))
        end,
    }
    _fdmap[fd] = c
    gateserver.openclient(fd)
    if on_connect_fn then
        on_connect_fn(c)
    end
end

function handler.disconnect(fd)
    close_fd(fd)

end

function handler.error(fd, msg)
    close_fd(fd)
end

function handler.warning(fd, size)
end


local CMD = {}
function handler.command(cmd, source, ...)
    local f = assert(CMD[cmd], cmd)
    assert(f, cmd)
    return f(...)
end

function handler.open(source, conf)
    if on_open_fn then
        on_open_fn(CMD, conf)
    end
end

function CMD.send_data(fd, data, ...)
    local c = _fdmap[fd]
    assert(c, fd)
    local str = pack_message_fn(c, data)
    socketdriver.send(fd, netpack.pack(str))
end

function CMD.close_fd(fd)
    if _fdmap[fd] then
        socketdriver.close(fd)
        close_fd(fd)
    end
end

return function(param)
    on_open_fn      = param.on_open_fn
    handshake_fn    = param.handshake_fn
    on_message_fn   = param.on_message_fn
    pack_message_fn = param.pack_message_fn
    on_closefd_fn   = param.on_closefd_fn
    on_connect_fn   = param.on_connect_fn
    if param.CMD then
        for k,v in pairs(param.CMD) do
            CMD[k] = v
        end
    end
    gateserver.start(handler)
end
