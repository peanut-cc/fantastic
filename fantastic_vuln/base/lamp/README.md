# 关于 LAMP 环境构建

默认 `LAMP` 构建的是基于`PHP 7.2` ,如果是需要构建起他PHP版本，需要在构建的时候添加`--build-arg PHP_VERSION=7.3`

```bash
# 默认为7.2
docker build --build-arg -t hjzhaofan/vuln_lamp:7.2 .
docker build --build-arg PHP_VERSION=7.3 -t hjzhaofan/vuln_lamp:7.3 .
```
