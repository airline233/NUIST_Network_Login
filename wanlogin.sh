#!/bin/bash

#================================================================================
# OpenWrt 校园网多拨自动登录脚本
#
# 功能:
# 1. 每分钟通过 cron 运行，检查所有 WAN 接口的网络连通性。
# 2. 仅针对 IP 地址为 10.0.0.0/8 网段的接口进行操作（校园网内网特征）。
# 3. 如果接口网络不通，则自动获取登录所需的 IP 地址。
# 4. 从 accounts.txt 文件中为每个离线接口分配一个账号。
# 5. 使用获取到的信息，模拟POST请求进行登录认证。
# 6. 将详细操作记录到日志文件 /tmp/wanlogin.log。
# 7. 在标准输出中打印关键登录结果。
#================================================================================

#--- 可配置区域 ---
# 登录认证URL (请务必修改为你的实际登录URL)
LOGIN_URL="http://10.255.255.46/api/v1/login" # <<<<<<------ 【重要】请修改为实际的登录POST地址

# 获取内网IP的API地址
IP_API_URL="http://10.255.255.46/api/v1/ip"

# 用于检查外网连通性的地址 (建议使用稳定、快速响应的网站)
CHECK_TARGET="https://www.baidu.com"

# 脚本运行目录 (自动获取)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# 账号文件路径
ACCOUNTS_FILE="${SCRIPT_DIR}/accounts.txt"

# 日志文件路径
LOG_FILE="/tmp/wanlogin.log"
#--- 配置区域结束 ---


#--- 基础工具检查 ---
if ! command -v curl &> /dev/null; then
    echo "错误: curl 命令未找到。请先安装: opkg update && opkg install curl"
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "错误: jq 命令未找到。请先安装: opkg update && opkg install jq"
    exit 1
fi


#--- 函数定义 ---

# 日志记录函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 网络连通性检查函数
# 参数1: interface_name (例如 pppoe-wan)
# 返回: 0 代表通畅, 1 代表不通
check_network() {
    local iface="$1"
    # 使用 --interface 参数强制通过指定网口发包
    # -s 静默模式, -o /dev/null 不输出内容, -w "%{http_code}" 只输出HTTP状态码
    # --connect-timeout 设置连接超时为5秒
    local http_code=$(curl --interface "$iface" --connect-timeout 5 -s -o /dev/null -w "%{http_code}" "$CHECK_TARGET")

    # 状态码为 200 (OK) 或 204 (No Content) 都认为网络是通的
    if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
        log "接口 [$iface] 网络正常 (HTTP Code: $http_code)。"
        return 0
    else
        log "接口 [$iface] 网络异常 (HTTP Code: $http_code)，准备执行登录操作。"
        return 1
    fi
}


#--- 主逻辑 ---

# 检查账号文件是否存在且可读
if [ ! -r "$ACCOUNTS_FILE" ]; then
    log "错误: 账号文件不存在或无法读取: $ACCOUNTS_FILE"
    echo "错误: 账号文件不存在或无法读取: $ACCOUNTS_FILE"
    exit 1
fi

# 读取并打乱账号顺序，以便实现随机和轮询分配
# 使用 shuf 命令（需要安装 coreutils-shuf）或者 sort -R
if command -v shuf &> /dev/null; then
    mapfile -t ACCOUNTS < <(shuf "$ACCOUNTS_FILE")
else
    mapfile -t ACCOUNTS < <(grep -vE '^\s*$' "$ACCOUNTS_FILE" | sort -r)
fi

# 检查账号数量
NUM_ACCOUNTS=${#ACCOUNTS[@]}
if [ "$NUM_ACCOUNTS" -eq 0 ]; then
    log "错误: 账号文件为空: $ACCOUNTS_FILE"
    echo "错误: 账号文件为空: $ACCOUNTS_FILE"
    exit 1
fi
log "加载了 $NUM_ACCOUNTS 个账号。"

# 查找所有IP地址在 10.0.0.0/8 网段的接口 (适配多拨和单WAN)
# `ip -4 addr show` 列出IPv4地址
# `grep 'inet 10\.'` 筛选出校园网IP
# `awk '{print $NF}'` 提取最后一段，即接口名称
INTERFACES=($(ip -4 addr show | grep 'inet 10\.' | awk '{print $NF}'))

if [ ${#INTERFACES[@]} -eq 0 ]; then
    log "未找到 IP 地址为 10.x.x.x 的网络接口，脚本退出。"
    exit 0
fi

log "发现需要检查的接口: ${INTERFACES[*]}"

account_index=0
# 遍历所有找到的接口
for iface in "${INTERFACES[@]}"; do
    # 检查网络是否通畅
    if check_network "$iface"; then
        # 网络通畅，跳过此接口
        continue
    fi

    # --- 网络不通，执行登录流程 ---

    # 1. GET内网IP
    # 使用 --interface 强制通过当前检测的接口获取IP
    log "正在为接口 [$iface] 获取内网IP..."
    ip_response=$(curl --interface "$iface" --connect-timeout 5 -s -X GET "$IP_API_URL")
    myip=$(echo "$ip_response" | jq -r '.data')

    # 验证获取到的IP是否有效
    if [ -z "$myip" ] || [[ ! "$myip" =~ ^10\. ]]; then
        log "接口 [$iface] 获取内网IP失败或IP格式不正确。返回内容: $ip_response"
        ip link set "$iface" down && ip link set "$iface" up
        if [ "$flag" = 1 ]; then
            continue
        fi
        flag = 1
    fi
    log "接口 [$iface] 获取到内网IP: $myip"

    # 2. 读取并解析账号信息
    # 使用模运算 (%) 来循环使用账号列表
    current_account_line=${ACCOUNTS[$account_index]}
    account_index=$(( (account_index + 1) % NUM_ACCOUNTS ))

    # 使用IFS(内部字段分隔符)来解析 "username|password|channel"
    IFS=':' read -r username password channel <<< "$current_account_line"

    # 去除可能存在的\r字符
    channel=$(echo "$channel" | tr -d '\r')

    if [ -z "$username" ] || [ -z "$password" ]; then
        log "警告: 从 '$current_account_line' 中解析账号密码失败，跳过。"
        continue
    fi
    log "为接口 [$iface] 分配账号: $username"

    # 3. 构造POST的payload
    payload="{\"username\":\"$username\",\"password\":\"$password\",\"channel\":\"$channel\",\"ifautologin\":\"0\",\"pagesign\":\"secondauth\",\"usripadd\":\"$myip\"}"

    # 4. 发送POST请求进行登录
    log "接口 [$iface] 正在使用账号 [$username] 和 IP [$myip] 尝试登录..."
    login_return_data=$(curl --interface "$iface" --connect-timeout 5 -s \
        -X POST "$LOGIN_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: */*" \
        -H "Cache-Control: no-cache" \
        -d "$payload")
    login_http_code=$(echo "$login_return_data" | jq -r '.code')
    return_text=$(echo "$login_return_data" | jq -r '.data.text')

    # 5. 输出结果和日志
    if [ "$login_http_code" = "200" ]; then
        log "接口 [$iface] 登录成功！IP: $myip, 返回码: $login_http_code"
        # 按要求输出到标准输出
        echo "IP:$myip,code:$login_http_code"
    else
        log "接口 [$iface] 登录失败。IP: $myip, 账号: $username, 返回: $return_text"
        echo $payload
    fi

done

log "--- 本次检查任务结束 ---"