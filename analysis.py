#coding:utf-8
import sys
from virus_total import Analysis


argvs = sys.argv 
argc = len(argvs)

#コマンドライン上の引数が三つ入ってない場合に返すエラー
if (argc != 3):
	print('usage: #python %s analysis_results_id' % argvs[0])
	quit()

#引数三つの場合（三つ以外の場合は考えぬ）
else: 
	analysis = Analysis(int(argvs[1]),str(argvs[2]))

	analysis.virustotal()
	print('analysis_results updated at id = %s' % argvs[1])