#!/bin/bash

# start[默认] 启动 , stop 停止
CMD=$1
if [ -z $CMD ]; then
    CMD=start
fi

# debug[默认] 前台启动, release 后台启动 
MODE=$2
if [ -z $MODE ]; then
    MODE=debug
fi

CONFIG=$3
if [ -z $CONFIG ]; then
    CONFIG=config.lua
fi


TMP=$PATH
PATH=$TMP
ulimit -c unlimited

CUR_PATH=$PWD
PID_FILE=$CONFIG.pid
CONF_TEMP=$CONFIG.tmp
DEBUG_CONF=$CONFIG.debug

function make_conf(){
    cat $CONFIG >> $CONF_TEMP

    echo "daemon='$PID_FILE'" >> $CONF_TEMP
    echo "logger='log/$(basename $CONFIG).log'" >> $CONF_TEMP
  }

function start(){
    case "$MODE" in
        release)
            make_conf
            $SKYNET/skynet $CONF_TEMP
            sleep 1
            echo $CONFIG start with pid $(cat $PID_FILE)
            rm $CONF_TEMP
            LOG="log/$(basename $CONFIG).log-$(date '+%Y%m%d')"
            tail -n 50 -f $LOG
            ;;
        debug)
            make_conf
            sed -e 's/daemon/--daemon/' $CONF_TEMP > $DEBUG_CONF
            rm $CONF_TEMP
             $SKYNET/skynet $DEBUG_CONF
        ;;
        *)
    esac
}

function stop(){
  if [ ! -f $PID_FILE ] ;then
    echo "not found pid file $PID_FILE"
    exit 0
  fi

  pid=`cat $PID_FILE`
  exist_pid=`pgrep skynet | grep $pid`
  if [ -z "$exist_pid" ] ;then
    echo "have no $CONFIG server"
    exit 0
  else
    echo -n $"$pid $CONFIG server will killed"
    kill $pid
    echo
  fi
}

case "$CMD" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    MODE=release
    start
    ;;
  *)
    exit 2
esac
