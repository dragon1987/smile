/**
 * @author zhixin wen <wenzhixin2010@gmail.com>
 * extensions: https://github.com/vitalets/x-editable
 */

(function($) {

    'use strict';

    $.extend($.fn.bootstrapTable.defaults, {
        searchForm: "searchForm",
        method: 'get',                      //请求方式（*）
        uniqueId: "id",                     //每一行的唯一标识，一般为主键列
        dataType: "json",
        pagination: true,                   //是否显示分页（*）
        sidePagination: "server",
        pageNumber: 1,                       //初始化加载第一页，默认第一页
        pageSize: 20,                       //每页的记录行数（*）
        pageList: [10, 20, 50],        //可供选择的每页的行数（*）
        showRefresh: true,
        showColumns: true,
        iconSize: "outline",
        icons: {
            refresh: "glyphicon-repeat",
            columns: "glyphicon-list"
        }
    });

    var BootstrapTable = $.fn.bootstrapTable.Constructor,
        _init = BootstrapTable.prototype.init;

    BootstrapTable.prototype.initServer = function (silent, query, url) {
        var that = this,
            data = {},
            params= new Object() ,
            request;
            if(this.options.searchForm){
                var formParams= $(this.options.searchForm).serializeArray()
                for(var i=0; i<formParams.length;i+=1){
                    var obj=formParams[i];
                    if(obj.name!=undefined&&obj.name!=""){
                        params[obj.name] = obj.value;
                    }
                }
                params.searchText=this.searchText;
                params.sortName=this.options.sortName;
                params.sortOrder=this.options.sortOrder;
            }else{
                params = {
                    searchText: this.searchText,
                    sortName: this.options.sortName,
                    sortOrder: this.options.sortOrder
                };
            }

        if (this.options.pagination) {
            params.pageSize = this.options.pageSize === this.options.formatAllRows() ?
                this.options.totalRows : this.options.pageSize;
            params.pageNumber = this.options.pageNumber;
        }

        if (!(url || this.options.url) && !this.options.ajax) {
            return;
        }

        if (this.options.queryParamsType === 'limit') {
            if(this.options.searchForm){
                var formParams= $(this.options.searchForm).serializeArray()
                for(var i=0; i<formParams.length;i+=1){
                    var obj=formParams[i];
                    if(obj.name!=undefined&&obj.name!=""){
                        params[obj.name] = obj.value;
                    }
                }
                params.searchText=this.searchText;
                params.sortName=this.options.sortName;
                params.sortOrder=this.options.sortOrder;
            }else{
                params = {
                    searchText: this.searchText,
                    sortName: this.options.sortName,
                    sortOrder: this.options.sortOrder
                };
            }

            if (this.options.pagination) {
                params.offset = this.options.pageSize === this.options.formatAllRows() ?
                    0 : this.options.pageSize * (this.options.pageNumber - 1);
                params.limit = this.options.pageSize === this.options.formatAllRows() ?
                    this.options.totalRows : this.options.pageSize;
            }
        }
        if (!($.isEmptyObject(this.filterColumnsPartial))) {
            params.filter = JSON.stringify(this.filterColumnsPartial, null);
        }
        data = calculateObjectValue(this.options, this.options.queryParams, [params], data);
        $.extend(data, query || {});

        // false to stop request
        if (data === false) {
            return;
        }

        if (!silent) {
            this.$tableLoading.show();
        }
        request = $.extend({}, calculateObjectValue(null, this.options.ajaxOptions), {
            type: this.options.method,
            url:  url || this.options.url,
            data: this.options.contentType === 'application/json' && this.options.method === 'post' ?
                JSON.stringify(data) : data,
            cache: this.options.cache,
            contentType: this.options.contentType,
            dataType: this.options.dataType,
            success: function (res) {
                res = calculateObjectValue(that.options, that.options.responseHandler, [res], res);

                that.load(res);
                that.trigger('load-success', res);
                if (!silent) that.$tableLoading.hide();
            },
            error: function (res) {
                that.trigger('load-error', res.status, res);
                if (!silent) that.$tableLoading.hide();
            }
        });

        if (this.options.ajax) {
            calculateObjectValue(this, this.options.ajax, [request], null);
        } else {
            if (this._xhr && this._xhr.readyState !== 4) {
                this._xhr.abort();
            }
            this._xhr = $.ajax(request);
        }
    };

    var calculateObjectValue = function (self, name, args, defaultValue) {
        var func = name;

        if (typeof name === 'string') {
            // support obj.func1.func2
            var names = name.split('.');

            if (names.length > 1) {
                func = window;
                $.each(names, function (i, f) {
                    func = func[f];
                });
            } else {
                func = window[name];
            }
        }
        if (typeof func === 'object') {
            return func;
        }
        if (typeof func === 'function') {
            return func.apply(self, args);
        }
        if (!func && typeof name === 'string' && sprintf.apply(this, [name].concat(args))) {
            return sprintf.apply(this, [name].concat(args));
        }
        return defaultValue;
    };



    BootstrapTable.prototype.init = function () {
        _init.apply(this, Array.prototype.slice.apply(arguments));
        var that=this
        $(this.options.searchButton).click(function () {
            that.refresh()
        });
    }

})(jQuery);