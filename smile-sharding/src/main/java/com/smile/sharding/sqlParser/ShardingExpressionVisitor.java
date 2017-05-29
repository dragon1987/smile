package com.smile.sharding.sqlParser;

import com.smile.sharding.enums.SqlExpressionType;
import com.smile.sharding.sqlSession.SqlSessionHolder;
import net.sf.jsqlparser.expression.*;
import net.sf.jsqlparser.expression.operators.arithmetic.*;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.expression.operators.conditional.OrExpression;
import net.sf.jsqlparser.expression.operators.relational.*;
import net.sf.jsqlparser.schema.Column;
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
import org.apache.ibatis.mapping.MappedStatement;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ShardingExpressionVisitor implements StatementVisitor, SelectVisitor, ExpressionVisitor, SelectItemVisitor {

    private MappedStatement mappedStatement;

    public ShardingExpressionVisitor(MappedStatement mappedStatement) {
        this.mappedStatement = mappedStatement;
    }

    @Override
    public void visit(NullValue nullValue) {

    }

    @Override
    public void visit(Select select) {
        select.getSelectBody().accept(this);
    }

    public void visit(Function function) {
        if (function.getName().equalsIgnoreCase("count")) {
            SqlSessionHolder.setSqlExpressionType(mappedStatement.getId(), SqlExpressionType.COUNT);
        } else if (function.getName().equalsIgnoreCase("sum")) {
            SqlSessionHolder.setSqlExpressionType(mappedStatement.getId(), SqlExpressionType.SUM);
        } else if (function.getName().equalsIgnoreCase("min")) {
            SqlSessionHolder.setSqlExpressionType(mappedStatement.getId(), SqlExpressionType.MIN);
        } else if (function.getName().equalsIgnoreCase("max")) {
            SqlSessionHolder.setSqlExpressionType(mappedStatement.getId(), SqlExpressionType.MAX);
        }
    }

    @Override
    public void visit(SignedExpression signedExpression) {

    }

    @Override
    public void visit(JdbcParameter jdbcParameter) {

    }

    @Override
    public void visit(JdbcNamedParameter jdbcNamedParameter) {

    }

    @Override
    public void visit(DoubleValue doubleValue) {

    }

    @Override
    public void visit(LongValue longValue) {

    }

    @Override
    public void visit(DateValue dateValue) {

    }

    @Override
    public void visit(TimeValue timeValue) {

    }

    @Override
    public void visit(TimestampValue timestampValue) {

    }

    @Override
    public void visit(Parenthesis parenthesis) {

    }

    @Override
    public void visit(StringValue stringValue) {

    }

    @Override
    public void visit(Addition addition) {

    }

    @Override
    public void visit(Division division) {

    }

    @Override
    public void visit(Multiplication multiplication) {

    }

    @Override
    public void visit(Subtraction subtraction) {

    }

    @Override
    public void visit(AndExpression andExpression) {

    }

    @Override
    public void visit(OrExpression orExpression) {

    }

    @Override
    public void visit(Between between) {

    }

    @Override
    public void visit(EqualsTo equalsTo) {

    }

    @Override
    public void visit(GreaterThan greaterThan) {

    }

    @Override
    public void visit(GreaterThanEquals greaterThanEquals) {

    }

    @Override
    public void visit(InExpression inExpression) {

    }

    @Override
    public void visit(IsNullExpression isNullExpression) {

    }

    @Override
    public void visit(LikeExpression likeExpression) {

    }

    @Override
    public void visit(MinorThan minorThan) {

    }

    @Override
    public void visit(MinorThanEquals minorThanEquals) {

    }

    @Override
    public void visit(NotEqualsTo notEqualsTo) {

    }

    @Override
    public void visit(Column column) {

    }

    @Override
    public void visit(SubSelect subSelect) {

    }

    @Override
    public void visit(CaseExpression caseExpression) {

    }

    @Override
    public void visit(WhenClause whenClause) {

    }

    @Override
    public void visit(ExistsExpression existsExpression) {

    }

    @Override
    public void visit(AllComparisonExpression allComparisonExpression) {

    }

    @Override
    public void visit(AnyComparisonExpression anyComparisonExpression) {

    }

    @Override
    public void visit(Concat concat) {

    }

    @Override
    public void visit(Matches matches) {

    }

    @Override
    public void visit(BitwiseAnd bitwiseAnd) {

    }

    @Override
    public void visit(BitwiseOr bitwiseOr) {

    }

    @Override
    public void visit(BitwiseXor bitwiseXor) {

    }

    @Override
    public void visit(CastExpression castExpression) {

    }

    @Override
    public void visit(Modulo modulo) {

    }

    @Override
    public void visit(AnalyticExpression analyticExpression) {

    }

    @Override
    public void visit(ExtractExpression extractExpression) {

    }

    @Override
    public void visit(IntervalExpression intervalExpression) {

    }

    @Override
    public void visit(OracleHierarchicalExpression oracleHierarchicalExpression) {

    }

    @Override
    public void visit(RegExpMatchOperator regExpMatchOperator) {

    }

    @Override
    public void visit(JsonExpression jsonExpression) {

    }

    @Override
    public void visit(RegExpMySQLOperator regExpMySQLOperator) {

    }


    public void visit(PlainSelect plainSelect) {
        if (plainSelect.getSelectItems() != null) {
            for (Iterator joinsIt = plainSelect.getSelectItems().iterator(); joinsIt.hasNext(); ) {
                SelectItem selectItem = (SelectItem) joinsIt.next();
                selectItem.accept(this);
            }
        }
        if (plainSelect.getOrderByElements() != null) {
            List<OrderBy> orderBies = new ArrayList<OrderBy>();
            for (Iterator joinsIt = plainSelect.getOrderByElements().iterator(); joinsIt.hasNext(); ) {
                OrderByElement orderByElement = (OrderByElement) joinsIt.next();
                OrderBy orderBy = new OrderBy();
                orderBy.setName(SqlSessionHolder.getProperty(mappedStatement.getId(), orderByElement.getExpression().toString(), mappedStatement.getResultMaps()));
                orderBy.setAsc(orderByElement.isAsc());
                orderBies.add(orderBy);
            }
            SqlSessionHolder.setOrderBy(mappedStatement.getId(), orderBies);
        }
    }

    @Override
    public void visit(SetOperationList setOperationList) {

    }

    @Override
    public void visit(WithItem withItem) {

    }


    @Override
    public void visit(AllColumns allColumns) {

    }

    @Override
    public void visit(AllTableColumns allTableColumns) {

    }

    @Override
    public void visit(SelectExpressionItem selectExpressionItem) {
        selectExpressionItem.getExpression().accept(this);
    }


    @Override
    public void visit(Delete delete) {

    }

    @Override
    public void visit(Update update) {

    }

    @Override
    public void visit(Insert insert) {

    }

    @Override
    public void visit(Replace replace) {

    }

    @Override
    public void visit(Drop drop) {

    }

    @Override
    public void visit(Truncate truncate) {

    }

    @Override
    public void visit(CreateIndex createIndex) {

    }

    @Override
    public void visit(CreateTable createTable) {

    }

    @Override
    public void visit(CreateView createView) {

    }

    @Override
    public void visit(Alter alter) {

    }

    @Override
    public void visit(Statements statements) {

    }

    @Override
    public void visit(Execute execute) {

    }
}
