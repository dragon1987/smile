$.widget("ui.dialog", $.extend(true, {}, $.ui.dialog.prototype, {
    options: {
        modal: false,
        closeOnEscape: false,
        resizable:false,
        create: function (e, ui) {
            var dlg = $(this).dialog("widget");
            var maxzIdx = 0;
            var openedDlgs = $(".ui-dialog");
            if (openedDlgs.length > 0) {
                $.each(openedDlgs, function (idx, el) {
                    var zidx;
                    var $el = $(el);
                    if ($el.css("z-index") && $el.css("z-index") !== "") {
                        zidx = parseInt($el.css("z-index"));
                        if (zidx > maxzIdx) {
                            maxzIdx = zidx;
                        }
                    }
                });
            }
//            $("<script>").text('function closeMe(){$("div[aria-describedby='+ dlg.attr("aria-describedby") +']").dialog().dialog("close")}').appendTo(dlg);
//            dlg.find("button.dlg-close,a.dlg-close").on("click",function(){closeMe()});
            var overlayfor = "dialog-" + dlg.attr("aria-describedby");
            $('<div class="overlay" style="display: none; background-color: black;-moz-opacity: 0.3;  opacity:.30;  filter: alpha(opacity=30);width: 100%; border: medium none; height: 100%; position: fixed; left: 0pt; top: 0pt;"></div>').attr("overlayfor", overlayfor).appendTo("body");
            dlg.css("z-index", maxzIdx + 1);
            var overlayEle = $("div[overlayfor=" + overlayfor + "]");
            overlayEle.height($(window).height());
            overlayEle.css("z-index", maxzIdx);
            overlayEle.show()
        },
        focus: function (event, ui) {
            resizeGridWidth();
        },
        beforeClose: function (event, ui) {
            var dlg = $(this).dialog("widget");
            var overlayfor = "dialog-" + dlg.attr("aria-describedby");
            var overlayEle = $("div[overlayfor=" + overlayfor + "]");
            overlayEle.remove();
        },
        close: function (event, ui) {
            $(this).dialog("destroy"); // 关闭销毁
        }
    },
    _title: function (title) {
        var $title = this.options.title || "";
        if (("title_html" in this.options) && this.options.title_html == true) {
            title.html($title);
        } else {
            title.text($title);
        }
    }
}));


$.widget("ui.autocomplete", $.extend(true, {}, $.ui.autocomplete.prototype, {
    _renderItem : function(ul, item) {
        return $("<li></li>").data("item.autocomplete", item).append($("<a></a>").html(item.label)).appendTo(ul);
    }
}));

$.extend({
    jqopenDialog: function (url, opts, defaultBtn) {
        if (defaultBtn || defaultBtn === undefined) {
            $.extend(opts, {
                buttons: [{
                    text: "确 定",
                    "class": "btn btn-primary",
                    click: function () {
                        var cb = opts.callback;
                        if ($.isFunction(cb)) {
                            var rt = cb.call(this,this);
                            if(rt){
                            	$(this).dialog("close");
                            }
                        }else{
                            var jqForm = $(this).find("form").eq(0);
                            if(jqForm.length>0){
                                jqForm.submit();
                            }
                        }
                    }
                }, {
                    text: "关闭",
                    "class": "btn",
                    click: function () {
                        $(this).dialog("close"); // 关闭销毁
                    }
                }]
            });
        }
        $.ajax({
            url: url,
            method: opts.type || "GET",
            type: opts.type || "GET",
            contentType:opts.contentType || 'application/x-www-form-urlencoded; charset=UTF-8',
			data:$.extend({},opts.data),
            //dataType: 'json',
			async:false,
            success: function (data, status, xhr) {
                if (opts.dlgId) {
                    data = "<div id=" + opts.dlgId + ">" + data + " </div>"
                }
                $(data).dialog($.extend({
                    title: "<div class='widget-header widget-header-small header-color-blue'><span>" + opts.dlgTitle || "Untitled" + "</span></div>",
                    title_html: true,
                    width: opts.dlgWidth || '80%',
                    height: opts.dlgHeight || 480
                },opts));
            },
            error: function(xhr, status, error) {
                //console.log(error);
            }
        });
    },

    jqopenDialogWithDiv: function (div, opts, defaultBtn) {
        if (defaultBtn || defaultBtn === undefined) {
            $.extend(opts, {
                buttons: [{
                    text: "确 定",
                    "class": "btn btn-primary",
                    click: function () {
                        var cb = opts.callback;
                        if ($.isFunction(cb)) {
                            var rt = cb.call(this,this);
                            if(rt){
                            	$(this).dialog("close");
                            }
                        }else{
                            var jqForm = $(this).find("form").eq(0);
                            if(jqForm.length>0){
                                jqForm.submit();
                            }
                        }
                    }
                }, {
                    text: "关闭",
                    "class": "btn",
                    click: function () {
                        $(this).dialog("close"); // 关闭销毁
                    }
                }]
            });
        }
        $(div).dialog($.extend({
            title: "<div class='widget-header widget-header-small header-color-blue'><span>" + opts.dlgTitle || "Untitled" + "</span></div>",
            title_html: true,
            width: opts.dlgWidth || '80%',
            height: opts.dlgHeight || 480
        }, opts));
    }
});
