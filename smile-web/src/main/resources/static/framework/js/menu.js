var detailDiv = $("#permissionsView");
var menuUrlDiv = $("#menuUrlCheck");

var iconDiv = $("#iconCheck");

var setting = {
    view: {
        showLine: true,
        addHoverDom: this.addHoverDom,
        removeHoverDom: this.removeHoverDom,
        checkable: true,
        selectedMulti: true,
        dblClickExpand: false
    },
    data: {
        simpleData: {
            enable: true
        }
    },
    callback: {
        beforeClick: true,
        beforeEditName: this.beforeEditName,
        beforeRemove: this.beforeRemove,
        onRemove: this.onRemove,
        onClick: this.onClick
    },
    edit: {
        enable: true,
        drag: {
            isCopy: false,
            isMove: false
        },
        removeTitle: "删除",
        renameTitle: "编辑",
        showRemoveBtn: true,
        showRenameBtn: true
    }
};

function beforeRemove(treeId, node) {
    return confirm("确认删除" + node.name + "吗？");
}

function onRemove(e, treeId, node) {
    var ids = node.id;
    if (ids != null) {
        ids = getAllChildrenNodeIds(node, ids);
        $.ajax({
            type: "post",
            url: "delete",
            data: {
                "ids": ids
            },
            success: function () {
                closeDetail();
            }
        });
    }
}


function getAllChildrenNodeIds(treeNode, result) {
    if (treeNode.isParent) {
        var childrenNodes = treeNode.children;
        if (childrenNodes) {
            for (var i = 0; i < childrenNodes.length; i++) {
                result += ',' + childrenNodes[i].id;
                result = getAllChildrenNodeIds(childrenNodes[i], result);
            }
        }
    }
    return result;
}

function addHoverDom(treeId, treeNode) {
    var sObj = $("#" + treeNode.tId + "_span");
    if (treeNode.editNameFlag || $("#addBtn_" + treeNode.id).length > 0 || treeNode.id == null) return;
    if (treeNode.editNameFlag || $("#addBranch_" + treeNode.id).length > 0 || treeNode.id == null) return;
    if (treeNode.editNameFlag || $("#addMenu_" + treeNode.id).length > 0 || treeNode.id == null) return;
    var addBranch = "<span class='addBranch' id='addBranch_" + treeNode.id
        + "' title='新增分支' onfocus='this.blur();'>&nbsp;&nbsp;&nbsp;&nbsp;</span>";
    var addMenu = "<span class='addMenu' id='addMenu_" + treeNode.id
        + "' title='新增菜单' onfocus='this.blur();'>&nbsp;&nbsp;&nbsp;&nbsp;</span>";
    var addButton = "<span class='button add' id='addBtn_" + treeNode.id
        + "' title='新增按钮' onfocus='this.blur();'></span>";
    if (treeNode.menuLevel == 1) {
        sObj.after(addMenu);
        sObj.after(addBranch);
        var branch = $("#addBranch_" + treeNode.id);
        if (branch) branch.bind("click", function () {
            var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
            zTree.addNodes(treeNode, {
                pId: treeNode.id,
                name: "new branch",
                icon: "/resources/images/folder.jpg",
                "menuLevel": 1
            });
            return true;
        });
        var menu = $("#addMenu_" + treeNode.id);
        if (menu) menu.bind("click", function () {
            var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
            zTree.addNodes(treeNode, {pId: treeNode.id, name: "new menu", "menuLevel": 2});
            return true;
        });
    } else if (treeNode.menuLevel == 2) {
        sObj.after(addButton);
        var btn = $("#addBtn_" + treeNode.id);
        if (btn) btn.bind("click", function () {
            var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
            zTree.addNodes(treeNode, {
                pId: treeNode.id,
                name: "new button",
                icon: "/resources/images/leaftNode.jpg",
                "menuLevel": 3
            });
            return true;
        });
    }
}

function removeHoverDom(treeId, treeNode) {
    $("#addBtn_" + treeNode.id).unbind().remove();
    $("#addBranch_" + treeNode.id).unbind().remove();
    $("#addMenu_" + treeNode.id).unbind().remove();
}

function beforeEditName(treeId, treeNode) {
    var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
    showDetail(treeNode);
    zTree.selectNode(treeNode);
    return false;
}

function onClick(e, treeId, treeNode) {
    var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
    showDetail(treeNode);
    zTree.selectNode(treeNode);
    return false;
}

function showDetail(treeNode) {
	
	console.debug(treeNode);
    if (treeNode.id != 0) {
        detailDiv.show();
    } else {
        return closeDetail;
    }
    if (treeNode.menuLevel == 2) {
        menuUrlDiv.show();
    } else {
        menuUrlDiv.hide();
    }
    if (treeNode.pId == 0) {
        iconDiv.show();
    } else {
        iconDiv.hide();
    }
    $("#id").val(treeNode.id);
    $("#level").val(treeNode.level);
    $("#pId").val(treeNode.pId);
    $("#menuLevel").val(treeNode.menuLevel);
    $("#tId").val(treeNode.tId);
    $("#name").val(treeNode.name);
    $("#code").val(treeNode.code);


    $("#systemId").val(treeNode.systemId);
    $("#isHidden").val(treeNode.isHidden);
    $("#isHidden").chosen().trigger("chosen:updated");


    $("#menuIcon").val(treeNode.menuIcon);
    $("#menuUrl").val(treeNode.menuUrl);
    $("#levelOrder").val(treeNode.levelOrder);

    var checkUrl= $("#checkUrl").attr("value");
    if(treeNode.id){
        $("#name").attr("remote",checkUrl+"?id="+treeNode.id);
        $("#code").attr("remote",checkUrl+"?id="+treeNode.id);
    }else{
        $("#name").attr("remote",checkUrl);
        $("#code").attr("remote",checkUrl);
    }
}

function closeDetail() {
    detailDiv.hide();
    return false;
}

$(function () {
    for (i in zNodes) {
        var node = zNodes[i];
        if (node.pId == 0) {
            node.open = true;
        }
    }
    $.fn.zTree.init($("#permissionsTree"), setting, zNodes);

    $("#createFolder").bind("click", {
        isParent: true
    }, function () {
    });
    closeDetail()
    $("#cancel").bind("click", closeDetail);
    $("#confirm").bind("click", function(){
        $.ajax({
            type: "POST",
            url: $('#permissionForm').attr("action"),
            data: $( "#permissionForm" ).serialize(),
            dataType: "json",
            success: function (response) {
                var data = $("#permissionForm").serializeArray();
                var zTree = $.fn.zTree.getZTreeObj("permissionsTree");
                var node;
                $.each(data, function (i, field) {
                    if (field.name == "tId") {
                        node = zTree.getNodeByTId(field.value);
                    }
                });
                if (node) {
                    node.id = response;
                    $.each(data, function (i, field) {
                        if (field.name == "name") {
                            node.name = field.value;
                        } else if (field.name == "code") {
                            node.code = field.value;
                        } else if (field.name == "menuUrl") {
                            node.menuUrl = field.value;
                        } else if (field.name == "levelOrder") {
                            node.levelOrder = field.value;
                        } else if (field.name == "menuIcon") {
                            node.menuIcon = field.value;
                        } else if (field.name == "systemId") {
                            node.systemId = field.value;
                        } else if (field.name == "isHidden") {
                            node.isHidden = field.value;
                        }
                    });
                    zTree.updateNode(node);
                    zTree.selectNode(node);
                    closeDetail();
                }
            },

        });

    });
});
