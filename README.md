============================================

ネットワークログから故障データを抽出する自分用のサンプルソフト。

============================================

--------------------------------------------------------------------------------

h3. テスト環境

* Windows 10
* Python 3.8.10 (tags/v3.8.10:3d8993a, May  3 2021, 11:48:03) [MSC v.1928 64 bit (AMD64)] on win32

h3. 依存ライブラリ

* netaddr (Q4のみ)

```
    > pip install netaddr
```
--------------------------------------------------------------------------------

## Q1.

監視ログから、故障状態のサーバのアドレスと故障期間を表示する。  

対象のログファイルは、ファイルパスを第2引数で指定することで入力できる。  
対象期間は、故障を観測した最初の時間～最後に故障を観測した最後の時間、とする。  

実行方法

```bash
    > python q01/01.py [file_path]
```

出力例

```bash
    192.168.1.1/24,2020-10-19 13:23:28,2020-10-19 13:23:28
    10.20.30.1/16,2020-10-19 13:30:40,2020-10-19 13:30:40
    10.20.30.1/16,2020-10-19 14:33:24,----/--/-- --:--:--
    10.20.30.2/16,2020-10-19 13:32:22,2020-10-19 14:00:25
```
--------------------------------------------------------------------------------

## Q2.

Q1にN回以上タイムアウトを繰り返したもののみ返すオプションを追加したもの。  

Nは、`--min-access-count`オプションで指定できる。  
指定ファイルは`--file`オプションで検出するよう変更。  

実行方法

```bash
    > python q02/02.py --file [file_path] --min-access-count [N]
```

出力例

```bash
    > python q02/02.py --file testdata/02/log.txt
    10.20.30.2/16,2020-10-19 13:32:22,2020-10-19 13:34:22
    10.20.30.1/16,2020-10-19 13:33:24,2020-10-19 13:37:24
    192.168.1.2/24,2020-10-19 13:52:35,2020-10-19 13:52:35
    > python 02/02.py --file testdata/02/log.txt --min-access-count 2
    2020-10-19 13:32:22,10.20.30.2/16,0:00:03
```

内容
    ServerLogParserのクラスでデータの処理を行う。  
    ParseLogFile関数で対象のファイル内の同一のIPアドレスのデータを一度集めて、それぞれに集計動作をさせる。  
    GetBrokenInfoで結果の生成をする。  
    配列(ファイル)の上から順にログ内を検索して、N回数以上エラーが検出された後、  
    エラーではないログを検出する1つ前までの期間を故障期間とし、1つのエラーとして出力する。(エラーではないログの行は故障機関に含めない)  
    エラーになった後、回復したログがない場合は、故障継続とみなして"----/--/-- --:--:--"を出力する。  

--------------------------------------------------------------------------------

## Q3.

Q2に直近 m[回] の応答時間が t[ms] 以上の場合は、過負荷であるとの表示をする機能を追加したもの。  

複数のデータを出力するため、データヘッダ"##??"の後に内容が出力される。  
m,tは、`--overload`オプションで指定できる。  

実行方法

```bash
    > python 03/03.py --file [file_path] --overload [m,t]
```

出力例

```bash
    > python ./q03/03.py --file ./testdata/03/log1.txt --overload 2,110
    ## broken
    10.20.30.1/16,2020-10-19 14:33:24,2020-10-19 14:33:24
    192.168.1.2/24,2020-10-19 13:52:35,2020-10-19 13:52:35

    ## overload
    10.20.30.1/16,2020-10-19 13:32:34,2020-10-19 13:43:24
```

--------------------------------------------------------------------------------

## Q4.

Q3にネットワークスイッチのエラー検出を追加.
複数のデータを出力するため、"##switch_broken"データヘッダが付く。


内容
    ※追加分のみ説明
    IPアドレスから、サブネットマスク分を取り除いたアドレスが同一の場合、同一のネットワークにいるものとする。
    Q2で得られた故障期間の重複を調べる。

    1. ログから、ネットワークに対するIP一覧を生成する
    2. IP一覧から、同一ネットワークのものを1つのログバッファに入れる
    3. ログバッファを時間順に検索し、エラーになっているIPアドレスの数をカウントする
    4. ネットワーク内のものと同数の時、スイッチのエラー時間として検出する

備考
    ログ内にある同一ネットワークのすべてのIPのエラーが検出された期間のみエラーとして扱う。
    ※途中でIPが増減することは想定しない

    ※残念ながらたぶん作りかけです、、、

--------------------------------------------------------------------------------
