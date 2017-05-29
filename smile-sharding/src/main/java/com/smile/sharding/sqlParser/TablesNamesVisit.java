package com.smile.sharding.sqlParser;

import com.smile.sharding.router.ISubtableRouterManager;
import net.sf.jsqlparser.expression.*;
import net.sf.jsqlparser.expression.operators.arithmetic.*;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.expression.operators.conditional.OrExpression;
import net.sf.jsqlparser.expression.operators.relational.*;
import net.sf.jsqlparser.schema.Column;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.StatementVisitor;
import net.sf.jsqlparser.statement.Statements;
import net.sf.jsqlparser.statement.alter.Alter;
import net.sf.jsqlparser.statement.create.index.CreateIndex;
import net.sf.jsqlparser.statement.create.table.CreateTable;
import net.sf.jsqlparser.statement.create.view.CreateView;
import net.sf.jsqlparser.statement.delete.Delete;
import net.sf.jsqlparser.statement.drop.Drop;
import net.sf.jsqlparser.statement.execute.Execute;
import net.sf.jsqlparser.statement.insert.Insert;
import net.sf.jsqlparser.statement.replace.Replace;
import net.sf.jsqlparser.statement.select.*;
import net.sf.jsqlparser.statement.truncate.Truncate;
import net.sf.jsqlparser.statement.update.Update;
import org.apache.commons.lang3.StringUtils;

public class TablesNamesVisit implements StatementVisitor, SelectVisitor, FromItemVisitor, ExpressionVisitor, ItemsListVisitor {

    private ISubtableRouterManager subtableRouterManager;

    private Object params;


    public TablesNamesVisit(ISubtableRouterManager subtableRouterManager, Object params) {
        this.subtableRouterManager = subtableRouterManager;
        this.params = params;
    }


    public void visit(WithItem withItem) {
        withItem.getSelectBody().accept(this);
    }

    public void visit(PlainSelect plainSelect) {
        plainSelect.getFromItem().accept(this);
        if (plainSelect.getJoins() != null) {
            for (Join join : plainSelect.getJoins()) {
                join.getRightItem().accept(this);
            }
        }
        if (plainSelect.getWhere() != null) {
            plainSelect.getWhere().accept(this);
        }
    }

    public void visit(Table tableName) {
        String newTable = subtableRouterManager.getRouterResult(tableName.getName(), params);
        if (StringUtils.isNotEmpty(newTable)) {
            tableName.setName(newTable);
        }
    }

    public void visit(SubSelect subSelect) {
        subSelect.getSelectBody().accept(this);
    }

    public void visit(Addition addition) {
        visitBinaryExpression(addition);
    }

    public void visit(AndExpression andExpression) {
        visitBinaryExpression(andExpression);
    }

    public void visit(Between between) {
        between.getLeftExpression().accept(this);
        between.getBetweenExpressionStart().accept(this);
        between.getBetweenExpressionEnd().accept(this);
    }

    public void visit(Column tableColumn) {
    }

    public void visit(Division division) {
        visitBinaryExpression(division);
    }

    public void visit(DoubleValue doubleValue) {
    }

    public void visit(EqualsTo equalsTo) {
        visitBinaryExpression(equalsTo);
    }

    public void visit(Function function) {
    }

    public void visit(GreaterThan greaterThan) {
        visitBinaryExpression(greaterThan);
    }

    public void visit(GreaterThanEquals greaterThanEquals) {
        visitBinaryExpression(greaterThanEquals);
    }

    public void visit(InExpression inExpression) {
        inExpression.getLeftExpression().accept(this);
        inExpression.getRightItemsList().accept(this);
    }

    public void visit(SignedExpression signedExpression) {
        signedExpression.getExpression().accept(this);
    }

    public void visit(IsNullExpression isNullExpression) {
    }

    public void visit(JdbcParameter jdbcParameter) {
    }

    public void visit(LikeExpression likeExpression) {
        visitBinaryExpression(likeExpression);
    }

    public void visit(ExistsExpression existsExpression) {
        existsExpression.getRightExpression().accept(this);
    }

    public void visit(LongValue longValue) {
    }

    public void visit(MinorThan minorThan) {
        visitBinaryExpression(minorThan);
    }

    public void visit(MinorThanEquals minorThanEquals) {
        visitBinaryExpression(minorThanEquals);
    }

    public void visit(Multiplication multiplication) {
        visitBinaryExpression(multiplication);
    }

    public void visit(NotEqualsTo notEqualsTo) {
        visitBinaryExpression(notEqualsTo);
    }

    public void visit(NullValue nullValue) {
    }

    public void visit(OrExpression orExpression) {
        visitBinaryExpression(orExpression);
    }

    public void visit(Parenthesis parenthesis) {
        parenthesis.getExpression().accept(this);
    }

    public void visit(StringValue stringValue) {
    }

    public void visit(Subtraction subtraction) {
        visitBinaryExpression(subtraction);
    }

    public void visitBinaryExpression(BinaryExpression binaryExpression) {
        binaryExpression.getLeftExpression().accept(this);
        binaryExpression.getRightExpression().accept(this);
    }

    public void visit(ExpressionList expressionList) {
        for (Expression expression : expressionList.getExpressions()) {
            expression.accept(this);
        }
    }

    public void visit(DateValue dateValue) {
    }

    public void visit(TimestampValue timestampValue) {
    }

    public void visit(TimeValue timeValue) {
    }

    public void visit(CaseExpression caseExpression) {
    }

    public void visit(WhenClause whenClause) {
    }

    public void visit(AllComparisonExpression allComparisonExpression) {
        allComparisonExpression.getSubSelect().getSelectBody().accept(this);
    }

    public void visit(AnyComparisonExpression anyComparisonExpression) {
        anyComparisonExpression.getSubSelect().getSelectBody().accept(this);
    }

    public void visit(SubJoin subjoin) {
        subjoin.getLeft().accept(this);
        subjoin.getJoin().getRightItem().accept(this);
    }

    public void visit(Concat concat) {
        visitBinaryExpression(concat);
    }

    public void visit(Matches matches) {
        visitBinaryExpression(matches);
    }

    public void visit(BitwiseAnd bitwiseAnd) {
        visitBinaryExpression(bitwiseAnd);
    }

    public void visit(BitwiseOr bitwiseOr) {
        visitBinaryExpression(bitwiseOr);
    }

    public void visit(BitwiseXor bitwiseXor) {
        visitBinaryExpression(bitwiseXor);
    }

    public void visit(CastExpression cast) {
        cast.getLeftExpression().accept(this);
    }

    public void visit(Modulo modulo) {
        visitBinaryExpression(modulo);
    }

    public void visit(AnalyticExpression analytic) {
    }

    public void visit(SetOperationList list) {
        for (PlainSelect plainSelect : list.getPlainSelects()) {
            visit(plainSelect);
        }
    }

    public void visit(ExtractExpression eexpr) {
    }

    public void visit(LateralSubSelect lateralSubSelect) {
        lateralSubSelect.getSubSelect().getSelectBody().accept(this);
    }

    public void visit(MultiExpressionList multiExprList) {
        for (ExpressionList exprList : multiExprList.getExprList()) {
            exprList.accept(this);
        }
    }

    public void visit(ValuesList valuesList) {
    }


    public void visit(IntervalExpression iexpr) {
    }

    public void visit(JdbcNamedParameter jdbcNamedParameter) {
    }

    public void visit(OracleHierarchicalExpression oexpr) {
    }

    public void visit(RegExpMatchOperator rexpr) {
        visitBinaryExpression(rexpr);
    }

    public void visit(RegExpMySQLOperator rexpr) {
        visitBinaryExpression(rexpr);
    }

    public void visit(JsonExpression jsonExpr) {

    }

    @Override
    public void visit(Select select) {
        select.getSelectBody().accept(this);
    }

    @Override
    public void visit(Delete delete) {
        delete.getTable().accept(this);
    }

    @Override
    public void visit(Update update) {
        for (Table table : update.getTables()) {
            table.accept(this);
        }
    }

    @Override
    public void visit(Insert insert) {
        insert.getTable().accept(this);
    }

    @Override
    public void visit(Replace replace) {
        throw new RuntimeException("replace is not suppert sharding table");
    }

    @Override
    public void visit(Drop drop) {
        throw new RuntimeException("drop is not suppert sharding table");
    }

    @Override
    public void visit(Truncate truncate) {
        throw new RuntimeException("truncate is not suppert sharding table");
    }

    @Override
    public void visit(CreateIndex createIndex) {
        throw new RuntimeException("createIndex is not suppert sharding table");
    }

    @Override
    public void visit(CreateTable createTable) {
        throw new RuntimeException("CreateTable is not suppert sharding table");
    }

    @Override
    public void visit(CreateView createView) {
        throw new RuntimeException("createView is not suppert sharding table");
    }

    @Override
    public void visit(Alter alter) {
        throw new RuntimeException("alter is not suppert sharding table");
    }

    @Override
    public void visit(Statements statements) {
        statements.accept(this);
    }

    @Override
    public void visit(Execute execute) {
        throw new RuntimeException("execute is not suppert sharding table");
    }
}
