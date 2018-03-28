python3.5で作成してます。

python2とpython3は互換性が無いためpython2では使用できません。
-------------------------------------------------------------------------
必要なもの

python3 

mysql.connector  python公式？のDB接続になります。

DL方法は調べたら出てきますが、piplistを保存しDLします。

これでpipコマンドが使用できるようになるので後はpipコマンドでmysql.connectorをDLしてください。

-------------------------------------------------------------------------
実行する場合

〇 python api_key.py をまず行ってください。

自動的にテーブル:virustotal_api_keysの中が更新（Apikeyが格納）されます。


〇 python3 analysis.py [更新したいクローラID] [指定するURL]　の引数3まで指定してください。

　analysis_resultsのshort_url_id,search_url,search_time,analysis_result,updated_atが更新されます。
 
 判定結果は0又は1にしてあります。
 
 現在しきい値としては、不正と判断された数/アンチウィルスサイトの総数を四捨五入して0又は1を出しています。
 
 よって現在では0は不正でない、1は不正であると判断されているということになります。
 
