local skynet = require 'skynet.manager'
local socket = require "skynet.socket"
local httpd        = require "http.httpd"
local sockethelper = require "http.sockethelper"
local cjson = require "cjson"
local cluster = require "skynet.cluster"


local CMD = {}
local _fds = {}
local _execute
local _resp_headers = {}
local MAX_READER = 65535

local function send_response(fd, statuscode, header, body)
  local w = sockethelper.writefunc(fd)
  local ok, err = httpd.write_response(w, statuscode, body, header)
  if not ok then
    skynet.error(string.format("fd = %d, %s", fd, err))
  end
end

local function copy_resp_header()
    local h = {}
    for k, v in pairs(_resp_headers) do
        h[k] = v
    end
    return h
end

function CMD.start(execute, domains, max_reader)
    if max_reader then
        MAX_READER = max_reader
    end
    if execute then
        _execute = require(execute)
    else
        _execute = {
            check_request = function(request)
                return 200
            end,
            execute = function(request, response) 
                response:resp_json({status="ok", info="hello world!"})
            end,
        }
    end

    if domains and #domains then
        _resp_headers["Access-Control-Allow-Origin"] = table.concat(domains, ";")
        _resp_headers["Access-Control-Allow-Credentials"] = "true"
    end
end

function CMD.attach(fd, addr)
    socket.start(fd)
    _fds[fd] = os.time()
    local reader = sockethelper.readfunc(fd)
    skynet.fork(function()
        while _fds[fd] do
            local code, url, method, header, body = httpd.read_request(reader, MAX_READER)
            if not code then
                _fds[fd] = nil
                break
            end
            if code ~= 200 then
                socket.close(fd)
                _fds[fd] = nil
                break
            end

            local request = {
                url = url,
                method = method,
                header = header,
                code = code,
                body = body,
                addr = addr,
                get_cookies = function(self)
                    local cookie = self.header["cookie"]
                    if not cookie then
                        return {}
                    end
                    local h = {}
                    for k, v in string.gmatch(cookie, "([^=;%s]+)=([^=;%s]+)") do
                        h[k] = v
                    end
                    return h
                end,
            }

            local response = {
                header = copy_resp_header(),
                cookies = {},
                code = 200,
                resp = function(self, body)
                    send_response(fd, self.code, self.header, body)
                end,
                resp_json = function(self, data)
                    local js = cjson.encode(data)
                    send_response(fd, self.code, self.header, js)
                end,
                add_cookie = function(self, value)
                    local header = self.header
                    if header["Set-Cookie"] then
                        header["Set-Cookie"] = header["Set-Cookie"] .. "\r\nSet-Cookie: " .. value 
                    else
                        header["Set-Cookie"] = value
                    end
                end,
                clear_cookie = function(self)
                    self.cookies = {}
                end,
            }

            local check_code, err = _execute.check_request(request, response)
            if check_code ~= 200 then
                response.code = check_code
                response:resp(err)
                socket.close(fd)
                _fds[fd] = nil
                return
            end
            _fds[fd] = os.time()
            _execute.execute(request, response)

            if not header["connection"] or header["connection"] ~= "keep-alive" then
                socket.close(fd)
                _fds[fd] = nil
                break
            end
        end
    end)
end

local function check_fds()
    local now = os.time()
    for fd, t in pairs(_fds) do
        if now - t > 10 then
            socket.close(fd)
            _fds[fd] = nil
        end
    end
    skynet.timeout(500, check_fds)
end

skynet.start(function()
    skynet.timeout(500, check_fds)
    skynet.dispatch("lua", function(session, source, cmd, ...)
        local fn = CMD[cmd]
        if not fn then
            fn = _execute[cmd]
        end
        assert(fn, cmd)
        return skynet.retpack(fn(...))
    end)
end)
