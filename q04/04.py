import os
import sys
import re
from datetime import datetime
from statistics import mean
import netaddr
from collections import namedtuple

NowTime = datetime.now()
server_status = []

class LogLine:
    address = "0.0.0.0",
    break_datetime = datetime.min
    state = ""
    response_time = -1

    def Parse(self, line : str):
        """
        Description:
            1行のデータパラメータ分解する
        Args:
            line = 1行のデータ
            ex.) "20201019133124,10.20.30.1/16,2"
            年月日時分秒,IPアドレス/プレフィックス,応答時間
        Returns:
            {
                address : "サーバアドレス",  # string
                datetime : timestamp,       # dateetime 
                response_time : 応答時間[ms],   # int 
                status : 状態                   # "" : OK , "-" :break
            }
        """
        line = line.rstrip()
        splt = line.split(',')            
        self.address = splt[1]
        self.datetime =  datetime.strptime(splt[0], '%Y%m%d%H%M%S')

        if splt[2].isdecimal():
            self.response_time = int(splt[2])
            self.state = ""
        else:
            self.state = splt[2]  # ischara

        return self
    
    def __str__(self):
        js = {
            "address" : self.address, 
            "datetime" : self.datetime,
            "response_time" : self.response_time,
            "state" : self.state
        }
        return str(js)
    

class ServerLogParser:
    """_summary_

    Returns:
    """
    broken_codes = ["-"]
    ServerLogs = {}
    Return_data = {
        "broken":[],
        "overload":[]
    }

    def __init__(self, filename : str = ""):
        if filename != "":
            self.ParseLogFile(filename)
        return

    def ParseLogFile(self, filename : str):
        """
        Description:
            ログの中から、故障したことがあるサーバを特定する。
            得られる故障期間を出力するが、回復しない場合は現在までの時間を算出する。
            重複がある場合は、
        Args:
            対象にするログファイルのパス
        Returns:
            {
                "サーバアドレス" : [
                        {
                            <LogLine>
                        },
                        {
                            # 繰り返し 
                        }
                    ],
                ... # 繰り返し
            }

        """
        # clear
        self.ServerLogs = {}

        # 上から読んでエラーを見つけたらserver_statusに突っ込む
        with open(filename,"r",encoding="utf-8") as fin:
            for line in fin:
                line = line.rstrip()
                self.__LogAppend(line)
        
        # アドレス毎に時間順にログをソートする
        for addr in self.ServerLogs:
            self.ServerLogs[addr].sort(key=lambda x: x.datetime)
        
        return iter(self.ServerLogs)

    def GetInfo(self, min_access_count : int = 0, overload_average_count : int = 10, overload_limit_time_ms : int = 180000):
        """サーバー毎にログをパースして、応答がないipに関する情報を返す

        Args:
            min_access_count (int, optional): 最低の連続アクセス回数. Defaults to 0.
            overload_average_count (int, optional): _description_. Defaults to 10.
            overload_time_ms (int, optional): _description_. Defaults to 180000.

        Returns:
            _type_: 故障、または、

        """
        self.Return_data = {
            "broken":[],
            "overload":[],
            "switch_broken":[]
        }

        # 各アドレス事の検査
        for addr in self.ServerLogs:
            server_logs = self.ServerLogs[addr]

            # 故障チェック
            ret = self.__checkBroken(server_log=server_logs, min_access_count=min_access_count)
            self.Return_data["broken"].extend(ret)

            # オーバーロードのチェック
            # -- ループ重複は気にしない
            ret = self.__checkOverload(server_log=server_logs, overload_limit_ms=overload_limit_time_ms, overload_average_count=overload_average_count)
            self.Return_data["overload"].extend(ret)
        
        # 同一ネットワークのエラーチェック
        ret = self.__checkSwitchBroken()
        self.Return_data["switch_broken"].extend(ret)

        return self.Return_data        

    def OutputResult(self):
        """動作結果をリストにして返すだけの関数

        Returns:
            _type_: _description_
        """
        result = []
        for key in self.Return_data:
            result.append(f"## {key}")
            for x in self.Return_data[key]:
                result.append(x)
            result.append("")
        
        return result

    def __LogAppend(self, logline : str):
        """ 1行のログをLogLineに変換して、ServerLogsにアドレス別に入れる

        Args:
            logline (str): ログの1行
        Returns:
            なし
        """
        log = LogLine()
        p = log.Parse(logline)
        addr = p.address
        if addr not in self.ServerLogs.keys():
            self.ServerLogs[addr] = []
        self.ServerLogs[addr].append(log)

    def __checkBroken(self, server_log: list, min_access_count : int = 0):
        """サーバの故障期間のデータを収集する内部関数

        Args:
            server_log (list): 
            ip_address (str): 対象サーバのipアドレスが入ってる

        Returns:
            _type_: _description_
        """
        bBroken = False
        return_data= []
        current_access_count = 0
        dt_last_broken = datetime.min
        dt_first_broken = datetime.min

        for log in server_log:

            if log.state == "-":
                if bBroken == False:
                    current_access_count = 0
                    dt_first_broken = log.datetime
                dt_last_broken = log.datetime
                current_access_count += 1
                bBroken = True

            else:
                if bBroken == True and current_access_count >= min_access_count:
                    restxt = f"{log.address},{dt_first_broken},{dt_last_broken}"
                    return_data.append(restxt)
                bBroken = False

        # not repaired
        if bBroken == True and current_access_count >= min_access_count:
            restxt = f"{log.address},{dt_first_broken},----/--/-- --:--:--"
            return_data.append(restxt)

        return return_data


    def __checkOverload(self,
        server_log: list, overload_average_count : int = 10, overload_limit_ms : int = 180000):
        """ サーバ事に過負荷の時間を計算する
        Description:
            過負荷の時間を計算する
            応答なしの場合は、時間に含めずskipする。

        Args:
            server_log (list): _description_
            ip_address (str): _description_
            overload_average_count (int, optional): 平均化する回数. Defaults to 10.
            overload_time_ms (int, optional): _description_. Defaults to 180000.
        """
        return_data = []
        newest_response_times = [] # 最新m回のデータ
        first_overload_time = None
        last_overload_time = None   # log.datetimeにすると、過負荷ではない状態を観測した時間になる

        for log in server_log:
            restime = log.response_time

            # skip check
            if log.state == "-" or log.response_time == -1:
                # エラーの時に回数リセットするならここでリストを空にする
                continue

            # 最新
            newest_response_times.append(log.response_time)
            newest_response_times = newest_response_times[-overload_average_count:]

            # 規定回数に満たないならskip
            if len(newest_response_times) != overload_average_count:
                continue

            # 平均時間
            ave = int(mean(newest_response_times))
            if ave >= overload_limit_ms:
                # 過負荷の場合
                if first_overload_time is None:
                    first_overload_time = log.datetime
                last_overload_time = log.datetime    # 記録するのを過負荷ではない結果を得た時間にする場合はここを消す
            else:
                # 過負荷を抜けた場合
                if first_overload_time is not None:
                    restxt = f"{log.address},{first_overload_time},{last_overload_time}"
                    return_data.append(restxt)
                first_overload_time = None

        if first_overload_time != None:
            restxt = f"{log.address},{first_overload_time},{last_overload_time}"
            return_data.append(restxt)
        first_overload_time = None

        return return_data


    def __checkSwitchBroken(self):
        """ネットワークスイッチの故障状態を出力する
        Returns:
            _type_: _description_
        Note:
        """
        def time_and(t_a_start, t_a_end, t_b_start, t_b_end):
            start = max(t_a_start, t_b_start)
            end = max(t_a_end, t_b_end)
            return {"start": start, "end": end }

        return_data = []
        broken_log = self.Return_data["broken"] # 
        networks = {}

        # ネットワーク一覧を生成
        for broken in broken_log:
            splt = broken.split(',')
            ipadr = splt[0]
            ip = netaddr.IPNetwork(ipadr)
            txt_ip_network = f"{ip.network}"
            if txt_ip_network not in networks:
                networks[txt_ip_network] = {}
                networks[txt_ip_network]["address"] = set()
                networks[txt_ip_network]["log"] = []
            networks[txt_ip_network]["address"].add(str(ip))
            networks[txt_ip_network]["log"].append(broken.split(','))


        # ネットワーク分繰り返す
        # ネットワーク一覧から
        return_data = []
        for netwk in networks:
            tgt = networks[netwk]

            # 開始時間順にログをソート
            tgt["log"].sort(key=lambda x: x[1])

            # エラーのフラグテーブルを生成
            flg_tables = {}
            for addr in tgt["address"]:
                flg_tables[addr] = {
                    "state" : 0,
                    "endtime" : datetime.max
                }
            
            # 時間順に検索して、エラーのフラグを立てる
            sw_crash_datetime = None
            last_end_time = None
            size = len(tgt["address"])

            sw_error_flag = 0
            for log in tgt["log"]:
                addr = log[0]
                starttime = log[1]
                endtime = log[2]
                current_datetime = datetime.strptime(starttime, '%Y-%m-%d %H:%M:%S')
                if endtime == "----/--/-- --:--:--":
                    end_datetime = datetime.max
                else:
                    end_datetime = datetime.strptime(endtime, '%Y-%m-%d %H:%M:%S')

                flg_tables[addr] = {
                    "state" : 1,
                    "endtime" : end_datetime
                }

                # total check -- すべてエラーかチェックする
                s = sum([flg_tables[d]["state"] for d in flg_tables])
                if s >= size:
                    sw_error_flag = 1
                    if sw_crash_datetime == None:
                        sw_crash_starttime = current_datetime
                    sw_crash_endtime = min([x["endtime"] for x in flg_tables.values()])
                    if sw_crash_endtime == datetime.max:
                        sw_crash_endtime = "----/--/-- --:--:--"
                    return_data.append(f"{netwk},{sw_crash_starttime},{sw_crash_endtime}")
                else:
                    if sw_error_flag == 1:
                        print(f"sw_crash_endtime === {sw_crash_endtime}")
                        sw_crash_endtime = min([x["endtime"] for x in flg_tables.values()])
                        sw_error_flag = 0

        return return_data


def get_param_from_argv(tag : str) -> str:
    """sys.argvのパラメータを取得する関数
    tagの直後の値を返す。直後の値がないときは空文字を返す

    Args:
        tag (str): パラメータヘッダ --file など

    Returns:
        str: 取得したパラメータ。エラー入力の時は空文字。
    """
    param = ""
    argv_length = len(sys.argv)
    if tag in sys.argv:
        idx = sys.argv.index(tag)
        idx1 = idx + 1
        if argv_length >= (idx1):
            param = sys.argv[idx1]
        else:
            param = ""
    
    return param


if __name__=="__main__":
    limit_time = 0
    argv_length = len(sys.argv)

    if argv_length < 2:
        print("please input text file path.")
        sys.exit()

    # min_access_count の抽出 # N指定
    cmd_key = "--min-access-count"
    min_access_count = get_param_from_argv(cmd_key)
    if min_access_count.isdecimal():
        min_access_count = int(min_access_count)
    else:
        min_access_count = 0

    # overload の抽出 # N指定
    cmd_key = "--overload"
    overload = get_param_from_argv(cmd_key)
    overload_m = 10     # 直近の平均回数
    overload_t = 1800   # オーバーロードとみなす平均応答時間
    splt = overload.split(',')
    if len(splt) == 2:
        overload_m = splt[0]
        overload_t = splt[1]
        if overload_m.isdecimal() and overload_t.isdecimal():
            overload_m = int(overload_m)
            overload_t = int(overload_t)

    # 対象ファイル名
    cmd_key = "--file"
    in_file = get_param_from_argv(cmd_key)
    if os.path.isfile(in_file):
        parser = ServerLogParser(in_file)
    else:
        print(f"target file not found : {in_file}")
        sys.exit()

    # メイン処理実行
    parser.GetInfo(
        min_access_count=min_access_count,
        overload_average_count=overload_m,
        overload_limit_time_ms=overload_t,
    )

    output = parser.OutputResult()

    for o in output:
        print(o)
    
    # スイッチのエラーを出力する

##-------------------------------------------------
## ----- テストコード
##-------------------------------------------------
testdata_path = "testdata/04"


def diff_test(in_txt : str, valid_txt : str, min_access_count: int, overload_average_count: int, overload_limit_time_ms: int):
    """テストデータとの照合をする。一致しなかったエラー行をすべて返す

    Args:
        ret (_type_): 関数の戻り値
        valid_txt (_type_): テスト用テキストのパス

    Returns:
        error_line: 比較でエラーになった行を積み上げる
    """
    error_line = []
    parser = ServerLogParser(in_txt)
    ret = parser.GetInfo(
        min_access_count=min_access_count,
        overload_average_count=overload_average_count,
        overload_limit_time_ms=overload_limit_time_ms)
    result = parser.OutputResult()

    with open(valid_txt, "r", encoding="utf-8") as fin:
        for r,v in zip(result,fin):
            r = r.rstrip()
            v = v.rstrip()
            print(r,v)
            if r != v:
                error_line.append(f"{r},{v}")

    return error_line


def test_log1():
    """テスト用のコード
    """
    global testdata_path
    test_txt = "log_1.txt"
    valid_txt = "valid_1.txt"

    min_access_count=0
    overload_average_count=2
    overload_limit_time_ms=200

    diffs = diff_test(
        in_txt = f"{testdata_path}/{test_txt}", 
        valid_txt = f"{testdata_path}/{valid_txt}",
        min_access_count=min_access_count,
        overload_average_count=overload_average_count,
        overload_limit_time_ms=overload_limit_time_ms,
    )

    assert diffs == []

def _test_log2():
    """テスト用のコード
    """
    global testdata_path
    test_txt = "log2.txt"
    valid_txt = "valid_2.txt"

    min_access_count=1
    overload_average_count=3
    overload_limit_time_ms=200

    diffs = diff_test(
        in_txt = f"{testdata_path}/{test_txt}", 
        valid_txt = f"{testdata_path}/{valid_txt}",
        min_access_count=min_access_count,
        overload_average_count=overload_average_count,
        overload_limit_time_ms=overload_limit_time_ms,
    )

    assert diffs == []
