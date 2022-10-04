import pandas as pd
import matplotlib.pyplot as plt
import sqlite3 as lite
from sqlite3 import Error
from pathlib import Path
from datetime import date
import numpy as np
import seaborn as sns
import matplotlib.ticker as tick
import requests
import difflib as diff
import re 
import csv
import ast

def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    conn = None
    try:
        conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
        # engine = sa.create_engine('sqlite:///' + db_file)  # connection via sqlalchemy
        # conn = engine.connect()
    except Error as e:
        print(e)
    return conn

# df_c_methods = pd.read_sql_query("SELECT m.name, m.signature, m.nloc, \
# m.parameters, m.token_count, m.code, m.before_change, f.programming_language FROM method_change m, file_change f \
# WHERE f.file_change_id=m.file_change_id AND f.programming_language='C'", conn)
# print(df_c_methods.head(5))

def convert_db_df():
    """
    """
    conn = create_connection(r"C:\Users\Administrator\Documents\CVEfixes_v1.0.0\Data\database.db")
    # query = """
 
    # SELECT cve.cve_id,cve.published_date, f.hash, com.author, repository.repo_name,file.file_change_id,method.method_change_id,cwe.cwe_name 
    # FROM cve,fixes f,commits com,repository,file_change file,method_change method,cwe,cwe_classification cc
    # WHERE 
    # file.file_change_id = method.file_change_id
    # and file.hash = com.hash
    # and com.repo_url = repository.repo_url
    # and cwe.cwe_id = cc.cwe_id
    # and cve.cve_id = cc.cve_id
    # and f.hash = com.hash

    # and cve.cve_id = f.cve_id;
    # """

    #   query = """
 
    # SELECT cve.cve_id,cve.published_date, f.hash, com.author, repository.repo_name,file.file_change_id,method.method_change_id,cwe.cwe_name 
    # FROM 
    # method_change method leftcve,fixes f,commits com,repository,file_change file,method_change method,cwe,cwe_classification cc
    # WHERE 
    # ;
    # """



    # c_single_line_fixes = pd.read_sql_query(query, conn)
    # c_single_line_fixes = c_single_line_fixes.sort_values(by=['cve_id', 'file_change_id'])
    # print(c_single_line_fixes.head(20))

    print("---------------------start--------------------")
 

    table_names = ["cve", "fixes", "commits", "repository", "file_change", "method_change", "cwe_classification", "cwe"]
    df_cve = pd.read_sql_query("SELECT * FROM cve", conn)
    df_fixes = pd.read_sql_query("SELECT * FROM fixes", conn)
    df_commits = pd.read_sql_query("SELECT * FROM commits", conn)
    # df_repository = pd.read_sql_query("SELECT * FROM repository", conn)
    df_file_change = pd.read_sql_query("SELECT * FROM file_change", conn)

    df_method_change = pd.read_sql_query("SELECT * FROM method_change", conn)
    df_cwe_classification = pd.read_sql_query("SELECT * FROM cwe_classification", conn)
    df_cwe = pd.read_sql_query("SELECT * FROM cwe", conn)



    df_cwec_cwe = pd.merge(df_cwe_classification,df_cwe, on = 'cwe_id', how='inner')
    df_cve_cwec_cwe = pd.merge(df_cve, df_cwec_cwe, on = 'cve_id', how = 'inner')
        #combine right group
    # df_com_rep = pd.merge(df_commits,df_repository,on = 'repo_url', how= 'left')
    df_file_meth = pd.merge(df_file_change,df_method_change,on = 'file_change_id', how= 'inner')
    df_com_file_math = pd.merge(df_commits,df_file_meth, on = 'hash', how= 'inner')
    df_fix_com_file_math = pd.merge(df_fixes,df_com_file_math, on = 'hash', how= 'inner' )
    df_all = pd.merge(df_cve_cwec_cwe,df_fix_com_file_math, on = 'cve_id',how='inner')          
 
    print("------------------combine end----------------")
    
    # df_all.to_csv(r"C:\Users\Administrator\Documents\CVEfixes_v1.0.0\Data\df_all_inner.csv",encoding='utf-8-sig')
   

 
    # print(df_cve_fixes.head(10))
    # print (df_all.shape while("code" is notnull) )
    # print(df_cve.shape)
    # print(df_fixes.shape)
    # print(df_cve_fixes_com.shape)
    # print(df_all.shape)

    
    df_temp = df_all[["cve_id", "cwe_id","cwe_name","code_before","code_after","diff","change_type","programming_language","diff_parsed"]]
    # df_temp = df_all[[ "cwe_id","cwe_name","code_before","code_after","diff","change_type","programming_language","diff_parsed"]]
    
    #统计cwe分布 
    # df_count = (df_temp['cwe_name'].str.len()
    #                 .groupby(df_temp['cwe_id'], sort=False).sum()
    #      ).to_frame(name='data_count').reset_index()
    # df_count = df_count.sort_values(by=['data_count'],ascending=False)     
    df_count = df_temp.groupby('cwe_id')['diff'].nunique().sort_values(ascending=False)
    
    
    print(df_count)


    df_new = df_temp.drop_duplicates(subset=['cwe_id', 'diff','diff_parsed'], keep='last')
    print(df_temp.shape)
    print(df_new.shape)
    # df_temp = df_temp.sort_values(by=['cve_id', 'file_change_id'])


    #导出样本表
    # df_sample = df_new.head(10)
    # print(df_sample)
    # df_sample = df_sample.applymap(lambda x: x.encode('unicode_escape').
    #              decode('utf-8') if isinstance(x, str) else x)
    # df_sample.to_excel(r'C:\Users\Administrator\Documents\CVEfixes_v1.0.0\Data\lite_sample.xlsx', index = False, header = True)
  
    # df_count = df_temp.drop_duplicates(subset=["cwe_id"])
    # print(df_count.shape)
    


    # df_list = []
    # for table_name in table_names:
    #     df_t = pd.read_sql_query("SELECT * FROM " + table_name, conn)
    #     print(table_name, df_t.shape)
        # if "cve_id" in df_t.columns.to_list():
        #     print(table_name)
        # if table_name == "fixes":
        #     print(f"{table_name}, {(df_t.columns.to_list())}")
        # df_list.append(df_t)
    # df = pd.concat(df_list)
    # print(len(df.columns.to_list()))
    # print()

if __name__ == "__main__":
    convert_db_df() 
