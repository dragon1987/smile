<#macro html>
<!DOCTYPE html>
<html lang="zh-CN">
    <#assign base = request.contextPath />
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!--360浏览器优先以webkit内核解析-->
    <title>H+ 后台主题UI框架 - 主页示例</title>
    <link rel="shortcut icon" href="${base}/favicon.ico">
    <link href="${base}/css/bootstrap.min.css?v=3.3.5" rel="stylesheet">
    <link href="${base}/css/font-awesome.min.css?v=4.4.0" rel="stylesheet">
    <link href="${base}/css/animate.min.css" rel="stylesheet">
    <link href="${base}/css/plugins/bootstrap-table/bootstrap-table.min.css" rel="stylesheet">
    <link href="${base}/css/plugins/chosen/chosen.css" rel="stylesheet">
    <link href="${base}/css/style.min.css?v=4.0.0"  rel="stylesheet">
</head>
<body class="gray-bg">
<script src="${base}/js/jquery.min.js?v=2.1.4"></script>
<script src="${base}/js/bootstrap.min.js?v=3.3.5"></script>
<script src="${base}/js/plugins/layer/layer.js"></script>
<script src="${base}/js/plugins/bootstrap-table/bootstrap-table.min.js"></script>
<script src="${base}/js/plugins/bootstrap-table/bootstrap-table-mobile.min.js"></script>
<script src="${base}/js/plugins/bootstrap-table/locale/bootstrap-table-zh-CN.min.js"></script>
<script src="${base}/js/plugins/bootstrap-table/bootstrap-table-default.js"></script>
<script src="${base}/js/plugins/chosen/chosen.jquery.js"></script>
<script src="${base}/js/common.js"></script>
    <#nested>
</body>
</html>
</#macro>