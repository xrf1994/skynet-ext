local table_insert = table.insert
local table_concat = table.concat
local string_format = string.format

local M = {}


function M.split(str, split)
    local list = {}
    local pos = 1
    if string.find("", split, 1) then -- this would result in endless loops
    error("split matches empty string!")
    end
    while true do
        local first, last = string.find(str, split, pos)
        if first then
            table_insert(list, string.sub(str, pos, first - 1))
            pos = last + 1
        else
            table_insert(list, string.sub(str, pos))
            break
        end
    end
    return list
end


-- 深拷贝
function M.copy(t, meta)
    local result = {}
    if meta then
        setmetatable(result, getmetatable(t))
    end

    for k, v in pairs(t) do
        if type(v) == "table" then
            result[k] = M.copy(v, nometa)
        else
            result[k] = v
        end
    end
    return result
end

-- 按哈希key排序
function M.spairs(t, cmp)
    local sort_keys = {}
    for k, v in pairs(t) do
        table.insert(sort_keys, {k, v})
    end
    local sf
    if cmp then
        sf = function (a, b) return cmp(a[1], b[1]) end
    else
        sf = function (a, b) return a[1] < b[1] end
    end
    table.sort(sort_keys, sf)

    return function (tb, index)
        local ni, v = next(tb, index)
        if ni then
            return ni, v[1], v[2]
        else
            return ni
        end
    end, sort_keys, nil
end

--反序列化
function M.unserialize(lua)
    local t = type(lua)
    if t == "nil" or lua == "" then
        return nil
    elseif t == "number" or t == "string" or t == "boolean" then
        lua = tostring(lua)
    else
        --print("can not unserialize a " .. t .. " type.")
    end
    lua = "return " .. lua
    local func = load(lua)
    if func == nil then
        return nil
    end
    return func()
end

--序列化
function M.serialize(obj, lvl)
    local lua = {}
    local t = type(obj)
    if t == "number" then
        table_insert(lua, obj)
    elseif t == "boolean" then
        table_insert(lua, tostring(obj))
    elseif t == "string" then
        table_insert(lua, string_format("%q", obj))
    elseif t == "table" then
        lvl = lvl or 0
        local lvls = ('  '):rep(lvl)
        local lvls2 = ('  '):rep(lvl + 1)
        table_insert(lua, "{\n")
        for k, v in pairs(obj) do
            table_insert(lua, lvls2)
            table_insert(lua, "[")
            table_insert(lua, M.serialize(k,lvl+1))
            table_insert(lua, "]=")
            table_insert(lua, M.serialize(v,lvl+1))
            table_insert(lua, ",\n")
        end
        local metatable = getmetatable(obj)
        if metatable ~= nil and type(metatable.__index) == "table" then
            for k, v in pairs(metatable.__index) do
                table_insert(lua, "[")
                table_insert(lua, M.serialize(k, lvl + 1))
                table_insert(lua, "]=")
                table_insert(lua, M.serialize(v, lvl + 1))
                table_insert(lua, ",\n")
            end
        end
        table_insert(lua, lvls)
        table_insert(lua, "}")
    elseif t == "nil" then
        return nil
    else
        --print("can not serialize a " .. t .. " type.")
    end
    return table_concat(lua, "")
end

function M.arr_concat(t1, t2)
    for i, v in ipairs(t2) do
        table.insert(t1, v)
    end
    return t1
end

function M.url_encode(s)
    s = string.gsub(s, "([^_^%w%.%- ])", function(c) return string.format("%%%02X", string.byte(c)) end)  
    return string.gsub(s, " ", "+")

--[[
    return (string.gsub(s, "([^A-Za-z0-9_])", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
]]
end

function M.url_decode(s)
    s = string.gsub(s, '%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
    return s
end

function M.load_file(path)
    local f = io.open(path, "r")
    local data = f:read("a")
    f:close()
    return data
end

return M
