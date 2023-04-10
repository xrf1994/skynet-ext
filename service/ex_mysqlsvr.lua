-- mysql 操作封装服务
-- auth:diandian
-- date:2017/6/15

local skynet = require 'skynet'
local mysql = require "skynet.db.mysql"
local cjson = require "cjson"
local ex_log = require "ex_log"

local NO_ERR = nil

local _db
local _dbname

local CMD = {}


local TS = tostring
local function QS(v)
    return mysql.quote_sql_str(TS(v))
end

function CMD.get(tname, key)
    local query = string.format("SELECT * FROM `%s` WHERE `key` = '%s';", tname, key)
    local res = _db:query(query)
    return res[0]
end

function CMD.get_table(tname, key)
    local query = string.format("SELECT * FROM `%s` WHERE `key` = '%s';", tname, key)
    local res = _db:query(query)
    if not res[1] then
        return nil
    end
    return cjson.decode(res[1].value)
end

function CMD.set(tname, key, value)
    local query
    if value then
        query = string.format(
            "REPLACE INTO `%s` (`key`, `value`) VALUES ('%s', '%s');", tname, key, value)
    else
        query = string.format(
            "DELETE FROM `%s` WHERE (`key`='%s');", tname, key)
    end
    return _db:query(query)
end

function CMD.set_table(tname, key, obj)
    local query
    if obj then
        query = string.format(
            "REPLACE INTO `%s` (`key`, `value`) VALUES ('%s', '%s');", tname, key, cjson.encode(obj))
    else
        query = string.format(
            "DELETE FROM `%s` WHERE (`key`='%s');", tname, key)
    end
    return _db:query(query)
end

function CMD.incr(tname, key)
    local query = string.format(
        "UPDATE `%s` SET `incr`=`incr`+1 WHERE `key`='%s'; SELECT `incr` FROM `%s` WHERE `key`='%s'",
        tname, key,  tname, key)
    local res = _db:query(query)
    return res[2][1].incr
end

function CMD.incr_init(tname, key, value)
    local query = string.format("SELECT * FROM `%s` WHERE `key`='%s';", tname, key)
    local res = _db:query(query)
    if res[1] then
        return res[1].incr
    end

    query = string.format("REPLACE INTO `%s` (`key`, `incr`) VALUES ('%s', %d);", tname, key, value)
    res = _db:query(query)
    return value
end

function CMD.desc_table(tname)
    local sql = string.format("show full columns from `%s`", tname)
    local res = _db:query(sql)
    if res.err then
        return res.err
    end
    return NO_ERR, res
end

local function db_heart()
    _db:query("use " .. _dbname)

    skynet.timeout(5000, db_heart)
end

function CMD.create_table(name, fields, prikey, index, comment)
    local sql = {}
    table.insert(sql, string.format("CREATE TABLE IF NOT EXISTS `%s` (", name))

    local body = {}
    for k, v in ipairs(fields) do
        local fs = string.format("`%s` %s %s NULL %s COMMENT \"%s\"",
                                    v.name, v.type, v.null or "", v.extra or "", v.comment or "")
        table.insert(body, fs)
    end
    if prikey then
        table.insert(body, string.format("PRIMARY KEY (%s)", prikey))
    end
    if index then
        for i, v in ipairs(index) do
            table.insert(body,
                string.format("INDEX `%s`(`%s`) USING %s",
                v.name, v.name, v.method))
        end
    end
    table.insert(sql, table.concat(body, ",\n"))

    table.insert(sql, string.format(") COMMENT \"%s\";", comment or ""))
    local sqltr = table.concat(sql, "\n")
    skynet.error("create table:\n", sqltr)
    local res = _db:query(sqltr)
    if res.err then
        return res.err
    end
    return NO_ERR, res
end

function CMD.drop_table(name)
    local sql = string.format("DROP TABLE `%s`;", name)
    skynet.error("drop table:\n", name)
    local res = _db:query(sql)
    if res.err then
        return res.err
    end
    return NO_ERR, res
end

local function insert_field(table_name, field_name, field)
    local sql = string.format(
        "ALTER TABLE `%s` ADD COLUMN `%s` %s %s NULL %s COMMENT \"%s\";",
        table_name, field_name, field.type, field.null or "", field.extra or "", field.comment or "")
    skynet.error("insert field:\n", sql)
    local res = _db:query(sql)
    if res.err then
        return res.err
    end
    return NO_ERR, res
end

local function modify_field(table_name, field_name, field)
    local sql = string.format(
        "alter table `%s` change `%s` `%s` %s %s NULL %s COMMENT \"%s\";",
        table_name, field_name, field_name, field.type, field.null or "", field.extra or "", field.comment or "")
    skynet.error("modify field:\n", sql)
    local res = _db:query(sql)
    if res.err then
        return res.err
    end
    return NO_ERR, res
end

local function check_fields(table_name, fields)
    local err, descs = CMD.desc_table(table_name)
    local cur_fields = {}
    for i, v in pairs(descs) do
        cur_fields[v.Field] = {
            type = v.Type,
            null = v.Null == "NO" and "NOT" or "",
            extra = v.Extra,
            comment = v.Comment,
        }
    end

    local creates = {}
    local executes = {}

    for i, v in ipairs(fields) do
        if cur_fields[v.name] then
            executes[v.name] = v
        else
            assert(v.name, v.comment)
            creates[v.name] = v
        end
    end

    for k, v in pairs(creates) do
        local err, res = insert_field(table_name, k, v)
        assert(not err, err)
    end

    local ckmap = { "type", "null", "extra", "comment", }
    for k, v in pairs(executes) do
        local sv = cur_fields[k]
        for i, f in ipairs(ckmap) do
            if v[f] and sv[f] and string.upper(v[f]) ~=  string.upper(sv[f]) then
                skynet.error("field diff:", f, v[f], "~=", sv[f])
                local err, res = modify_field(table_name, k, v)
                assert(not err, err)
                break;
            end
        end
    end
end

local function check_index(tn, index)
    local sql = string.format("show index from `%s`", tn)
    local res = _db:query(sql)

    local cur_index = {}
    for i, v in ipairs(res) do
        cur_index[v.Column_name] = v
    end
    for i, v in ipairs(index) do
        if not cur_index[v.name] then
            local sql = [[ALTER TABLE `%s` ADD INDEX `%s`(`%s`) USING %s]]
            sql = string.format(sql, tn, v.name, v.name, v.method)
            ex_log.info(sql)
            local res = _db:query(sql)
            assert(not res.err, res.err)
        end
    end
end

function CMD.check_tables(registers)
    local query_tables = _db:query("show tables;")
    local cur_tables = {}
    for i, v in ipairs(query_tables) do
        local n = v[next(v)]
        cur_tables[n] = n
    end

    local creates = {}
    local deletes = {}
    local executes = {}

    for k, v in pairs(cur_tables) do
        if not registers[k] then
            deletes[k] = k
        else 
            executes[k] = registers[k]
        end
    end

    for k, v in pairs(registers) do
        if not cur_tables[k] then
            creates[k] = v
        end
    end

    for k, v in pairs(creates) do
        local err, res = CMD.create_table(v.name, v.fields, v.prikey, v.index, v.comment)
        assert(not err, err)
    end

    --[[ not delete table
    for k, v in pairs(deletes) do
        local err, res = CMD.drop_table(k)
        assert(not err, err)
    end
    --]]

    for k, v in pairs(executes) do
        check_fields(k, v.fields)
    end

    for k, v in pairs(registers) do
        if v.index then check_index(k, v.index) end
    end
end

function CMD.query(sql)
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.select(tname, fields, where, limit, extra)
    local sql = {
        "SELECT",
        table.concat(fields, ","),
        "FROM",
        tname
    }

    if where and next(where) then
        table.insert(sql, "WHERE")
        for _, v in ipairs(where) do
            if type(v) == "table" then
                table.insert(sql, string.format("%s%s", TS(v[1]), QS(v[2])))
            else
                table.insert(sql, TS(v))
            end
        end
    end

    if limit and next(limit) then
        table.insert(sql, "LIMIT")
        table.insert(sql, table.concat(limit, ","))
    end
    if extra then
        table.insert(sql, extra)
    end

    local sql = table.concat(sql, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.select_count(tname, where)
    local sql = {
        "SELECT count(*) FROM",
        string.format("`%s`", tname),
    }
    if where and next(where) then
        table.insert(sql, "WHERE")
        for _, v in ipairs(where) do
            if type(v) == "table" then
                table.insert(sql, string.format("%s%s", TS(v[1]), QS(v[2])))
            else
                table.insert(sql, TS(v))
            end
        end
    end
    local sql = table.concat(sql, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res[1]["count(*)"]
end


function CMD.insert(tname, data, exc)
    local tk = {}
    local tv = {}
    for k, v in pairs(data) do
        table.insert(tk, string.format("`%s`", TS(k)))
        table.insert(tv, QS(v))
    end
    local t = {
        "INSERT INTO",
        string.format("`%s`", tname),
        "(", table.concat(tk, ","), ")",
        "VALUES",
        "(", table.concat(tv, ","), ")",
        ";",
        exc,
    }

    local sql = table.concat(t, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.replace(tname, data, exc)
    local tk = {}
    local tv = {}
    for k, v in pairs(data) do
        table.insert(tk, string.format("`%s`", k))
        table.insert(tv, QS(v))
    end
    local t = {
        "REPLACE INTO",
        string.format("`%s`", tname),
        "(", table.concat(tk, ","), ")",
        "VALUES",
        "(", table.concat(tv, ","), ")",
        ";",
        exc,
    }

    local sql = table.concat(t, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.update(tname, fields, where, exc)
    local values = {}
    for k, v in pairs(fields) do
        table.insert(values, string.format("`%s`=%s", TS(k), QS(v)))
    end

    local sql = {
        "UPDATE",
         tname,
         "SET",
         table.concat(values, ","),
    }

    if where and next(where) then
        table.insert(sql, "WHERE")
        for _, v in ipairs(where) do
            if type(v) == "table" then
                table.insert(sql, string.format("%s%s", TS(v[1]), QS(v[2])))
            else
                table.insert(sql, TS(v))
            end
        end
    end
    if exc then
        table.insert(sql, TS(exc))
    end
    local sql = table.concat(sql, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err .. sql, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.delete(tname, where, exc)
    local sql = {
        "DELETE FROM",
        tname
    }
    if where and next(where) then
        table.insert(sql, "WHERE")
        for _, v in ipairs(where) do
            if type(v) == "table" then
                table.insert(sql, string.format("%s%s", TS(v[1]), QS(v[2])))
            else
                table.insert(sql, TS(v))
            end
        end
    end
    if exc then
        table.insert(sql, TS(exc))
    end
    local sql = table.concat(sql, " ")
    local res = _db:query(sql)
    if res.err then
        return res.err, ex_log.error("sql err:", res.err, sql)
    end
    return NO_ERR, res
end

function CMD.connect(config_, dbname_)
    local config = {
        host = config_.host or "127.0.0.1",
        port = config_.port or 3306,
        user = config_.user or "root",
        password = config_.password or "",
        database = dbname_,
        on_connect = function(db_)
            _db = db_
            skynet.error("mysql connected:", dbname_)
            end,
    }
    _dbname = dbname_
    ex_log.info("connecting mysql:", config_, dbname_)
    _db = mysql.connect(config)
end

skynet.start(function()
    skynet.timeout(5000, db_heart)
    skynet.dispatch("lua", function(session, source, cmd, ...)
        assert(CMD[cmd], cmd)
        return skynet.retpack(CMD[cmd](...))
    end)
end)
