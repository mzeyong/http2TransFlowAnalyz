#! /usr/bin/env python
# -*- coding : utf - 8
# Author : k2yk

import  os
import csv


import steamResource

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
DATA_TAB_5 = '\t\t\t\t\t '
TAB_1 = DATA_TAB_1 + '- '
TAB_2 = DATA_TAB_2 + '- '
TAB_3 = DATA_TAB_3 + '- '
TAB_4 = DATA_TAB_4 + '- '
TAB_5 = DATA_TAB_5 + '- '
TAB_6 = '\t' + TAB_5
TAB_7 = '\t' + TAB_6
DOMAINRULE = '[a-zA-Z0-9][-a-zA-Z0-9]+(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*(\.[a-zA-Z]{2,20})+'
UPGRADEASKRULE = 'http/1.1'
UPGRADERULE = 'h2'
SAVEPATH = os.getcwd()+'/dmath'
RESOURCEPOOL = steamResource.resourcePool()
TEMPDICT = {}
TEMPDOMAINDICT = {}


def read_csv_file(dictionnary,fileName):

	path = os.getcwd()+'/tls-1.2-test/tls/parameters/' + fileName
	with open(path,newline='') as csvfile:
		values = csv.reader(csvfile,delimiter=',')
		for row in values:
			if fileName == "cipher-suites.csv":
				hexa_suit = row[0]
				hexa_suit = hexa_suit.replace('0x','')
				hexa_suit = hexa_suit.replace(',','')
				hexa_suit = hexa_suit.lower()
				dictionnary[hexa_suit] = row[1]
			else:
				number = int(row[0])
				name = row[1]
				dictionnary[number] = name

#we need the cipher-suites
crypto_suites = {}
def init():
    read_csv_file(crypto_suites,"cipher-suites.csv")


