/**
 * Created by zhutao on 2016/7/30.
 */

function openWin(params) {
    $(params.button).on('click', function () {
        if (params.type == "del") {
            var rows = $(params.tableGrid).bootstrapTable('getSelections')
            if (rows.length < 1) {
                layer.alert('请至少选择一行', {
                    skin: 'layui-layer-molv' //样式类名
                    , closeBtn: 0
                }, function (index) {
                    layer.close(index);
                });
            } else {
                if (params.callback) {
                    params.callback
                } else {
                    layer.confirm(params.context, {
                        btn: ['是', '否'] //按钮
                    }, function (index) {
                        var ids = [];
                        for (var i = 0; i < rows.length; i++) {
                            ids.push(rows[i].id)
                        }
                        if(params.url){
                            $.post(params.url, {"ids": ids.join()}, function (data) {
                                $(params.tableGrid).bootstrapTable('refresh')
                                layer.close(index);
                            });
                        }else{
                            var findUrl = $(params.tableGrid).bootstrapTable('getOptions').url
                            var delUrl = findUrl.substring(0, findUrl.lastIndexOf("/")) + "/del";
                            $.post(delUrl, {"ids": ids.join()}, function (data) {
                                $(params.tableGrid).bootstrapTable('refresh')
                                layer.close(index);
                            });
                        }
                    }, function (index) {
                        layer.close(index);
                    });
                }
            }


        } else if (params.type == "add") {
            var loading = layer.load();
            $.get(params.url, function (data) {
                layer.close(loading);
                if (params.callback) {
                    layer.open({
                        type: 1,
                        closeBtn: 1,
                        title: params.title,
                        area: params.area,
                        content: data,
                        btn: params.btn
                        , yes: params.callback
                    });
                } else {
                    layer.open({
                        type: 1,
                        closeBtn: 1,
                        title: params.title,
                        area: params.area,
                        content: data,
                        btn: params.btn
                        , yes: function (index, layero) {
                            var findUrl = $(params.tableGrid).bootstrapTable('getOptions').url
                            var addUrl = findUrl.substring(0, findUrl.lastIndexOf("/")) + "/add";
                            $.post(addUrl, $(params.form).serialize(), function (data) {
                                $(params.tableGrid).bootstrapTable('refresh')
                                layer.close(index);
                            });
                        }
                    });
                }

            })
        } else if (params.type == "edit") {
            var rows = $(params.tableGrid).bootstrapTable('getSelections')
            if (rows.length == 0) {
                layer.alert('请选择一行', {
                    skin: 'layui-layer-molv' //样式类名
                    , closeBtn: 0
                }, function (index) {
                    layer.close(index);
                });
            } else if (rows.length > 1) {
                layer.alert('请只选择一行', {
                    skin: 'layui-layer-molv' //样式类名
                    , closeBtn: 0
                }, function (index) {
                    layer.close(index);
                });
            } else {
                var loading = layer.load();
                var url = params.url + "?id=" + rows[0].id
                $.get(url, function (data) {
                    layer.close(loading);
                    if (params.callback) {
                        layer.open({
                            type: 1,
                            closeBtn: 1,
                            title: params.title,
                            area: params.area,
                            content: data,
                            btn: params.btn
                            , yes: params.callback
                        });
                    } else {
                        layer.open({
                            type: 1,
                            closeBtn: 1,
                            title: params.title,
                            area: params.area,
                            content: data,
                            btn: params.btn
                            , yes: function (index, layero) {
                                var findUrl = $(params.tableGrid).bootstrapTable('getOptions').url
                                var editUrl = findUrl.substring(0, findUrl.lastIndexOf("/")) + "/edit";
                                $.post(editUrl, $(params.form).serialize(), function (data) {
                                    $(params.tableGrid).bootstrapTable('refresh')
                                    layer.close(index);
                                });
                            }
                        });
                    }
                });
            }
        }
    });

}
