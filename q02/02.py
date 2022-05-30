import os
import sys
import re
from datetime import datetime

NowTime = datetime.now()

server_status = []

class LogLine:
    address = "0.0.0.0",
    break_datetime = datetime.min
    repair_datetime = datetime.max
    downtime = 0
    state = ""

    def Parse(self, line : str):
        """
        Description:
            1行のデータパラメータ分解する
        Args:
            line = 1行のデータ
            ex.) "20201019133124,10.20.30.1/16,2"
            年月日時分秒,IPアドレス/プレフィックス,応答時間
        Returns:

        """
        line = line.rstrip()
        splt = line.split(',')
        self.address = splt[1]
        self.datetime =  datetime.strptime(splt[0], '%Y%m%d%H%M%S')
        self.downtime = -1
        self.state = splt[2]
        return self
    
    def __str__(self):
        js = {
            "address" : self.address, 
            "break_datetime" : self.break_datetime
        }
        return str(js)
    

class ServerLogParser:
    """_summary_

    Returns:
        {
            addr : "サーバアドレス", # string
            break_datetime : 故障開始の日時,          # dateetime 
            downtime : 故障時間,             # -1 : デフォルト値
            current_status : 現在の状態      # 0: 回復, 1: 故障
        }
    """
    broken_codes = ["-"]
    ServerLogs = {}

    def __init__(self, filename : str = ""):
        if filename != "":
            self.ParseLogFile(filename)
        return

    def _LogAppend(self, logline : str):
        """ サーバ毎のログに分割保存する

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
                self._LogAppend(line)
        
        return iter(self.ServerLogs)
    
    def GetBrokenInfo(self, min_access_count : int = 0):
        """
            サーバー毎に収集されたログを上から順に検索して、応答がないipに関する情報を返す。

        Args:
            min_access_count (int, optional): 最低の連続アクセス回数. Defaults to 0.

        Returns:
            _type_: _description_
        """
        return_data = []
        current_access_count = 0

        for addr in self.ServerLogs:
            bBroken = False

            server_logs = self.ServerLogs[addr]
            dt_first_broken = datetime.min
            dt_last_broken = datetime.min

            for log in server_logs:
                if log.state == "-":
                    if bBroken == False:
                        current_access_count = 0
                        dt_first_broken = log.datetime
                    current_access_count += 1
                    bBroken = True
                    dt_last_broken = log.datetime

                elif log.state != "-":
                    if bBroken == True and current_access_count >= min_access_count:
                        return_data.append(f"{addr},{dt_first_broken},{dt_last_broken}")
                        dt_first_broken = log.datetime
                        dt_last_broken = log.datetime
                    bBroken = False

            # not repaired
            if bBroken == True and current_access_count >= min_access_count:
                return_data.append(f"{addr},{dt_first_broken},----/--/-- --:--:--")

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

def test_cnt1():
    """テスト用のコード
    """
    testdata_path = "testdata/02"
    parser = ServerLogParser(f"{testdata_path}/log.txt")
    ret = parser.GetBrokenInfo(min_access_count=1)

    valid_data = open(f"{testdata_path}/valid_1.txt")
    error_line = []

    for r,v in zip(ret,valid_data):
        r = r.rstrip()
        v = v.rstrip()
        if r != v:
            error_line.append(f"{ret},{valid_data}")

    assert error_line == []


def test_cnt2():
    """テスト用のコード
    """
    testdata_path = "testdata/02"
    parser = ServerLogParser(f"{testdata_path}/log.txt")
    ret = parser.GetBrokenInfo(min_access_count=2)

    valid_data = open(f"{testdata_path}/valid_2.txt")
    error_line = []

    for r,v in zip(ret,valid_data):
        r = r.rstrip()
        v = v.rstrip()
        if r != v:
            error_line.append(f"{ret},{valid_data}")

    assert error_line == []

def test_cnt3():
    """テスト用のコード
    """
    testdata_path = "testdata/02"
    parser = ServerLogParser(f"{testdata_path}/log.txt")
    ret = parser.GetBrokenInfo(min_access_count=3)

    valid_data = open(f"{testdata_path}/valid_3.txt")
    error_line = []

    for r,v in zip(ret,valid_data):
        r = r.rstrip()
        v = v.rstrip()
        if r != v:
            error_line.append(f"{ret},{valid_data}")

    assert error_line == []

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

    # 対象ファイル名
    cmd_key = "--file"
    in_file = get_param_from_argv(cmd_key)
    if os.path.isfile(in_file):
        parser = ServerLogParser(in_file)
        ret = parser.GetBrokenInfo(min_access_count=min_access_count)
        for x in ret:
            print(x)
