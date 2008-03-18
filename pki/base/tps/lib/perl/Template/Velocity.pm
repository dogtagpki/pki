#!/usr/bin/pkiperl
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#


use strict;

package Template::Velocity::Executor;
sub new;

package Template::Velocity;


# The Template::Velocity package implements a Template execution
# engine similar to the Java Velocity package.

use Parse::RecDescent;
use Data::Dumper;


$Template::Velocity::parser;

our  $docroot="docroot";
our  $parser;
my %parsetrees = ();
my $debugflag = 0;


#GRAMMAR defined here

my $vmgrammar = q{

	{
			use Data::Dumper;
			sub Dumper
			{
				$::debugdumper = undef;
				if ($::debugflag && $::debugdumper ) { return Data::Dumper(@_); }
				else {""};
			}

	}
	

# Template is the top-level object
	template: <skip:'[ \t]*'> section(s) /\Z/

	section: blockdirective
		   | nonblockdirective
		   | plainline 

	blockdirective: ifblock
				  | foreachblock

	plainline : <skip:''> /[ \t]*/ ...!'#' linecomp(s?) /\n*/

	HASH: '#'

# HMM - this doesn't handle multiple variables on one line?
	linecomp: variable 
	        | <skip:'[ \t]*'> /[^\$\n]*/

	nonblockdirective: '#' 'include' <commit> includeargs /\n*/ {  $item[4] ; }
					 | '#' 'parse'   <commit> parseargs   /\n*/ {  $item[4] ; }
					 | '#' 'set'     <commit> setargs     /\n*/ {  $item[4] ; }
 					 | <error:unknown command $text>


	ifblock: ifdirective section(s) elseclause(?) enddirective 


# this bubbles up the result of the expression inside the if()
# which is from the 'ifargs' rule
 	ifdirective: '#' 'if' <skip:'[ \t]*'> ifargs /\n/  

 	enddirective: <skip:'[ \t]*'> '#' 'end' "\n"

	elseclause: elsedirective section(s) 

 	elsedirective: '#' 'else' "\n"

	foreachblock: foreachdirective section(s) enddirective

 	foreachdirective: '#' 'foreach' foreachargs "\n"

   ifargs:        '(' expression ')' 
			| <error:Argument to if must be an expression: $text>

   foreachargs:   '(' variablename 'in' variable ')'
			|  <error:Arguments to 'foreach' must be of form \$a in \$b: $text>

   includeargs:   '(' string ')'
			|  <error:invalid argument to include: $text>

   parseargs:   '(' expression ')'
			|  <error:invalid argument to parsearges: $text>


   setargs:   <skip:'[ \t]*'>  '(' assignment ')'  
			|  <error:Argument to set must be an assignment : $text>


# expression evaluation

# this goes roughly in order of precendence:
#   ==
#   &&, ||
#   +, -
#   *
#   !

# does not properly distinguish between lvalues and rvalues


    expression: boolean
			  | <error>


    assignment: variablename '=' boolean 

    boolean:    equality (boolean_operator equality)(?)

	boolean_operator:     ( '&&' | '||' )

	equality:   summation (equality_operator summation)(?)
			

	equality_operator:    ( '==' | '!=' )

    summation:   product (summation_operator summation)(?)

	summation_operator:   ( '+' | '-' )


# must parenthesize operator '*' to get it to appear in the $item array

    product:   negation ('*' product)(?)

#XXX need to implement
	negation:   notoperator(?) factor 

	notoperator: "!"

    factor:      number
		|        string
        |        variable



#  These rules deal with variables
#  handles $process
#          $file.executablename
#          $process.getpid()
#          $person.getparent().getbrother().slap()
#          $fred.getchildren()

#   You'd make a dependency on the 'variable' rule if you want the value
#   of the variable.
#   You'd make a dependency on the 'variablename' rule if you want the
#   name of the variable.
#   (There's no real difference here - the expression evaluation is
#   in the variable() subroutine)

	variable:  variablename { ["variable", $item[1][1] ]; }

	variablename: '$' identifier subfield(s?)
		{
			my $variableinfo = { 
					top    => $item{identifier}, 
					fields => $item{'subfield(s?)'}
				};
   			$return = [ "variablename", \$variableinfo ];
		}

	subfield:     '.' identifier arglist(?)
		{
			my $d;
			my $a = $item{"arglist(?)"};
			my $args;
			
			#::debug "arglist = ".Dumper($a)."\n";
			if ($a) {

				my ($argcount, $al, $alpresent);
			
				#$args = @{$a}->[2];
				$args = $a->[0][2];
				#::debug "arglist args=".Dumper($args)."\n";
				$alpresent = $args;
				$argcount = $#$args;
				if ($alpresent && $argcount == -1) {
					$args->[0] = [ ];
				}
			}

			#::debug "arglist identifier=".$item{identifier}."\n";
			$return = [ "subfield", { 
					fieldname => $item{identifier},
					arglist   => $args->[0],
					} ];
		}

	arglist:      '(' list(?) ')'

    list:         expression (',' list)(s?)
	

# Basic data types
# identifiers, numbers and strings

	identifier:  /[A-Za-z0-9_]+/ { $item[1]; }

    number: /\d+/   {$item[1]; }

	#XXX skip is all wrong here... should be in []
    string:   <skip:'[ \t]'>   '"' <skip:""> /[^"]*/ '"' { $return = ["string",$item[4]]; }
          |   <skip:'[ \t]'>   "'" <skip:""> /[^']*/ "'" { $return = ["string",$item[4]]; }


# other literals
	whitespace:  /\s*/

  
};


# Get a parser object (transforming the built-in text grammar into RecDescent
# data structure). This object can be reused for parsing multiple velocity files
sub new
{
	#$::debugflag = 0;
	my $class = shift;
	$docroot = shift;
	undef $::RD_HINT;
	undef $::RD_WARN;
	#$::RD_TRACE = 1;
	$parser = new Parse::RecDescent($vmgrammar) or die "Bad Grammar\n"; 
	$Data::Dumper::Maxdepth = 1;;
	my $self = {};
	$self->{parser} = $parser;
	# ugly - :-(
	$Template::Velocity::parser = $parser;
	bless $self, $class;
	return $self;
}


# Execute a template.  Given a text string and a parser object, will return
# a parse tree, useful for feeding into the executor.
sub execute_string
{
	my $self = shift;
	my $string = shift;
	my $rule = shift;
	if (! $rule ) { $rule = "template"; }
	#print Dumper($self);

	my $parser = $self->{parser};
	my $parsetree = $parser->$rule($string);
	my $executor = new Template::Velocity::Executor($parsetree, $parser );
	
	my @value = $executor->run();
	#my @value = Template::Velocity::Executor::execute($parsetree, $parser);
	my $value = shift @value;
	return $value;
}


sub execute_file
{

	my $self = shift;
	my $filename = shift;

	my $rule;
	my $tree = $parsetrees{$filename};

	if (! $tree) {
		$rule = "template";
		open my $fh, "<$docroot/$filename" or return undef;
		my $string = join "",<$fh>;
		close $fh;
		$tree = $parser->$rule($string);
		$parsetrees{$filename} = $tree;
	}
	
	my $executor = new Template::Velocity::Executor($tree, $parser );

	my @value = $executor->run();
	my $value = shift @value;
	return $value;
	

}








sub Dumper
{
 return "";
 if ($::debugflag && $::debugdumper) { 
	return Data::Dumper->Dump([@_]); 
 }
 else {""};
}




# This autoaction returns an array of each parse element
# The net result is a parse tree
# I couldn't use <autotree> because I wanted to preserve
# the order of the elements, and <autotree> returns a
# hashtable, not an array

$::RD_AUTOACTION = q{
   [@item];
};

# debug flags set here






#########   EXECUTE FUNCTIONS


# These functions deal with executing the velocity parse tree
{
	package Template::Velocity::Executor::Rules;
	use Data::Dumper;

	# this imports symbols from these other packages, so
    # we don't have to always use the fully-qualified names
	*exe_all      = \&Template::Velocity::Executor::exe_all;
	*exe_optional = \&Template::Velocity::Executor::exe_optional;
	*execute      = \&Template::Velocity::Executor::execute;
	*debug        = \&Template::Velocity::Executor::debug;
	*indent       = \&Template::Velocity::Executor::indent;
	*deindent     = \&Template::Velocity::Executor::deindent;
#XXX probably should be $, not &
	*docroot      = \&Template::Velocity::docroot;

	sub Dumper
	{
		return "";
 		if ($::debugflag && $::debugdumper) { return Dumper(@_); }
 		else {""};
	}

	#template: <skip:'[ \t]*'> section(s) /\Z/
	sub template {
		my $f = "template";
		my @item = exe_all(@_);
		debug ("$::level $f - sections should be an array of text: .".Dumper($item[2])."\n");
		my $sections = $item[2];
		debug ("sections is a: ".(ref $sections)." - it should be an array\n");
		my $r= ( join "", @{$item[2]});
		return $r;
	}
	

	#linecomp: variable 
	#        | <skip:'[ \t]*'> /[^\$\n]*/
	sub linecomp {
		my $item;
		debug ("linecomp: _[2] = '".$_[2]."'\n");
		if ($_[2]) {
			debug ("linecomp: inside if\n");
			$item = $_[1].$_[2];
		} else {
			debug ("linecomp: inside else{\n");
			($item) = exe_all($_[1]);
			debug ("linecomp: end of else}\n");
			debug ("linecomp: item =\n".Dumper($item)."\n");
		}
		debug ("linecomp: returning $item\n");
		return $item;
	}

	# plainline : <skip:''> /[ \t]*/ ...!'#' linecomp(s?) /\n+/
	sub plainline {
		my @item = exe_all(@_);
		debug ("$::level in plainline - linecomps should be an array of text: .".Dumper($item[4])."\n");
		my $r = join "", @{$item[4]};
		debug ("$::level in plainline - joined as: $r\n");
		$r = $item[2] . $r. $item[5];
		debug ("$::level in plainline - returning : $r\n");
		return $r;
	}

	sub expression {
		debug ("$::level expression  = ".Dumper($_[1])."\n");
		my ($item) = exe_all($_[1]);
		debug ("$::level expression returning $item\n");
		return $item;
	}

	#foreachblock: foreachdirective section(s) enddirective
	sub foreachblock {
		my $f = "foreachblock";
		debug ("$::level $f started!\n");
		my ($directive)  = exe_all($_[1]);
		debug ("$::level $f directive = \n".Dumper($directive)."\n");
		my ($variable, $list) = @{$directive};
		my $variablename = $$variable->{top};
		debug ("$::level $f variable = $variablename\n");
		debug ("$::level $f list = \n".Dumper($list)."\n");

		my $result = "";
		foreach my $q (@{$list}) {
			debug ("$::level $f q=$q\n");
			$::symbol{$variablename} = $q;
			debug ("$::level $f setting variable $variablename = $q\n");
			
			my ($sections)  = exe_all($_[2]);
			debug ("$::level $f sections was: ".Dumper($sections)."\n");
			$result .= join "",@{$sections};
		}
		return $result;
	}

 	#foreachdirective: '#' 'foreach' foreachargs "\n"
	sub foreachdirective {
		my ($item) = exe_all($_[3]);
		return $item;
	}

    #foreachargs:   '(' variablename 'in' expression ')'
	sub foreachargs {
		my $f = "foreachargs";
		my ($variable, $list) = exe_all($_[2], $_[4]);
		debug ("$::level $f variable = \n".Dumper($variable)."\n");
		debug ("$::level $f list = \n".Dumper($list)."\n");
		return [$variable, $list];
	}

	# XXX if block should only execute section(s) if if arg is positve)
	# likewise for else
	#ifblock: ifdirective section(s) elseclause(?) enddirective 
	sub ifblock {
		my $f = "ifblock";
		my @item = exe_all(@_);
		debug ("$::level $f - sections should be an array of text: .".Dumper($item[2])."\n");
		my $sections = $item[2];
		my $else = $item[3];
		debug ("$::level $f sections is a: ".(ref $sections)." - it should be an array\n");
		debug ("$::level   item1: if expression = ".$item[1]."\n");
		debug ("$::level $f elseclause is a: ".(ref $else)." - it should be an scalar\n");
		my $r= ( 
				$item[1]>0 ?                           # if expression
					(join "", @{$item[2]}) : 
					($item[3] ? join "",@{$item[3]} : "")
			   );
		# this is not quite right ... elseclause returns a scalar (it joins the sections)
		# so why do I have to join again here? possibly because it's a '?'
		return $r;
	}

	#elseclause: elsedirective section(s) 
	sub elseclause {
		my $f = "elseclause";
		my ($sections) = exe_all($_[2]);
		debug ("$::level $f sections is a: ".(ref $sections)." - it should be an array\n");
		my $return = join "", @{$sections};
		debug ("$::level $f returning: $return\n");
		return $return;
	}

	sub ifargs {
		debug ("$::level ifargs [2] = ".Dumper($_[2])."\n");
		my ($item) = exe_all($_[2]);
		debug ("$::level item  = ".Dumper($item)."\n");
		my $r = $item>0 ? 1 : 0;  
		debug ("$::level ifargs returning $r\n");
		return $r;
	}

 	#ifdirective: '#' 'if' <skip:'[ \t]*'> ifargs /\n/  
	sub ifdirective {
		my ($item) = exe_all($_[4]);
		my $r = $item>0 ? 1 : 0;  
		debug ("$::level ifdirective returning $r\n");
		return $r;
	}

    #boolean:    equality (boolean_operator equality)(?)
	sub boolean {
		my $f = "boolean";
		my ($equality, $alt) = ( execute($_[1]), $_[2]);
		my $r = $equality;
		if (scalar @$alt) {
			my ($op, $equality2) = exe_optional($alt, 1,2);

			if ($op eq '&&') { 
				$r = $equality && $equality2;
			}
			if ($op eq '||') {
				$r = $equality || $equality2;
			}
		}

		return $r;
	}


    #summation:   product (summation_operator summation)(?)
	sub summation {
		#my @item = exe_all(@_);
		my $f = "summation";
		my ($product, $alt) = ( execute($_[1]), $_[2]);
		debug("$::level $f - product = $product, alternation = $alt\n");
		debug("$::level $f - alternation = \n".Dumper($alt)."\n");

		if (scalar @$alt) {
			if (0) {
			debug("$::level $f - alt1= \n".Dumper($alt->[0][1])."\n");
			debug("$::level $f - alt2= \n".Dumper($alt->[0][2])."\n");
			my ($operator, $summation) = ( execute($alt->[0][1]), execute($alt->[0][2]),);
			}
			my ($operator, $summation) = exe_optional($alt, 1,2);

			if ($operator eq '+') { return $product + $summation;
			} else { return $product - $summation; }
		} else {
			return $product;
		}
	}

	

	#equality:   summation (equality_operator summation)(?)
	sub equality {
		my $f = "equality";
		my ($summation, $alt) = ( execute($_[1]), $_[2] );

		if (scalar @$alt) {
			my ($operator, $summation2) = exe_optional($alt, 1,2);

			# string comparison used, so (0.0) is NOT equal to (0)
			if ($operator eq '==') { return ($summation eq $summation2) ? 1:0; }
			else { return ($summation eq $summation2) ? 0:1; }
		} else {
			return $summation;
		}
	}


	sub product {
		my $f = "product";
		my ($negation, $alt) = ( execute($_[1]), $_[2]);
		debug("$::level $f negation = $negation, alternation = $alt\n");
		debug("$::level $f - alternation = ".Dumper($alt)."\n");

		if (scalar @$alt) {
			if (0) {
			debug("$::level $f - alt1= \n".Dumper($alt->[0][1])."\n");
			debug("$::level $f - alt2= \n".Dumper($alt->[0][2])."\n");
			my ($operator, $product) = ( execute($alt->[0][1]), execute($alt->[0][2]),);
			}
			my ($operator, $product) = exe_optional($alt,1,2);
			return ($negation * $product);
		} else {
			return $negation;
		}
	}

	sub factor {
		my ($value) = exe_all($_[1]);
		return $value;
	}

	#negation:   notoperator(?) factor 
	sub negation {
		debug ("$::level in negation... input = ".(join ",",@_)."\n");
		#my @item = exe_all(@_);
		my ($alt, $value) = ( $_[1], execute($_[2]) );
		debug ("$::level negation: alternation= $alt\n");
		debug ("$::level negation: value = $value\n");
		my $operator = execute($alt->[0][1]);

		my $r;
		if ($operator && $operator eq '!') {
			if ($value ) { $r = 0; }
			else { $r = 1; }
			debug ("$::level negation: inverting\n");
		} else {
			debug ("$::level negation: not inverting\n");
			$r = $value;
		}
		debug ("$::level negation: returning $r\n");
		return $r;
	}

   #setargs:   <skip:'[ \t]*'>  '(' assignment ')'  
	sub setargs {
		my $f = "setargs";
		my ($args) = exe_all($_[3]);
		debug("$::level $f args = \n".Dumper($args)."\n");
		my ($variable, $value) = @{$args};
		debug("$::level $f variable type =".(ref $variable)."\n");
		debug("$::level $f variable = \n".Dumper($variable)."\n");
		my $symbolname = $$variable->{top};
		debug("$::level $f setting variable '$symbolname' = $value\n");
		$::symbol{$symbolname} = $value;
		return "";
	}

    #assignment: variablename '=' boolean 
	sub assignment { 
		my $f = "assignment";
		my ($variable, $value) = exe_all($_[1],$_[3]);
		debug("$::level $f variable = \n".Dumper($variable)."\n");
		my $r = [ $variable, $value ];
		debug("$::level $f returning: \n".Dumper($r)."\n");
		return $r;
	}

   	#includeargs:   '(' string ')'
	sub includeargs {
		my $f = "includeargs";
		my ($filename ) = execute($_[2]);

		debug("including file: $filename\n");
		open my $fh, "<$docroot/$filename" or return "filenotfound $docroot/$filename!\n";
		my $file = join "", <$fh>;
		close FILE;
		
		return $file;
	}

	sub parseargs {
		my $f = "parseargs";
		my ($filename ) = execute($_[2]);

		debug("parsing file: $filename\n");
		
		#open my $fh, "<$docroot/$filename" or return "filenotfound $docroot/$filename!\n";
		#my $file = join "", <$fh>;
		#close FILE;

		#my $parsetree = $Template::Velocity::parser->template($file);
		#my @value = execute($parsetree);
		#my $value = shift @value;

		my @value = Template::Velocity::execute_file(undef,$filename);
		my $value = shift @value;

		return $value;
	}

# variables

# variables
# this rule converts a variable name/identifier into its value
# $main.subfield(argument1,argument2).subfield2(arg1,arg2)
# There are two data structures at work here.
#  1. the data structure specifying the variable name to be queried
# this represents  $a.b.c(100,9,5,4)
#{
# 'top' => 'a'
# 'fields' => [
#   { 'fieldname' => 'b', 'arglist' => undef },
#   { 'fieldname' => 'c', 'arglist' => [ '100', 9, 5, '4', ], }
#   ],
#}
#  2. Data structure specifying the symbol table

# return value could be:
#  a scalar: either a string/number value or reference to an array of values
#  an array
 
	sub  variable {
# look up the root object in the symbol table
		my $f = "variable";
		debug("$::level $f: input\n".Dumper(\@_)."\n");
		my $var    = $_[1];
		debug("$::level $f var=\n".Dumper($var)."\n");
# $$var works with # 27:   '#set (\$a=1+3)\n\$a\n'
#0  REF(0x8fa0510)
#   -> HASH(0x8fa1454)
#        'fields' => ARRAY(0x8fa8c08)
#            empty array
#        'top' => 'a'

# $var works with # 25:   '$employee.add(100,4+5,2+3,4,4,5,6)'
#DB<2> x $var
#0  HASH(0x9c7a340)
#  'fields' => ARRAY(0xa06e7d8)
#  0  ARRAY(0xa06e9ac)
#     0  'subfield'
#     1  HASH(0xa06e880)
#        'arglist' => ARRAY(0xa074184)

		my $top    = $$var->{top};    # name of the root object
			debug("$::level $f top=\n".Dumper($top)."\n");
		my $fields  = $$var->{fields}; # array of the subidentifiers
			my $val    = "";

		debug("$::level $f - top_id = $top\n");
		debug("$::level $f : var: \n".Dumper($var)."\n");
		debug("$::level $f - fields = \n".Dumper($fields)."\n");


		debug("$::level $f : top = ".$top."\n");
		if (! defined $::symbol{$top} ) {
# XXX
			debug ("symbol table = ",(join ",",sort keys %::symbol)."\n");
			debug ("undefined variable: $top\n");
			return 0;
		}
		debug("$::level $f symbol table: \n".Dumper(\%::symbol)."\n");
		$val = $::symbol{$top};
		debug("$::level $f val before: \n".Dumper($val)."\n");

		debug("$::level $f - fields = \n".Dumper($fields)."\n");
		my $pass = 1;
		foreach my $field (@$fields) {
			my $args;

			my ($fieldname, $values);
			{
				debug("$::level $f pass $pass \@_=\n".Dumper(\@_)."\n");
				debug("$::level $f before strip field = \n".Dumper($field)."\n");
#shift @$fn;   # 'subfield' string
#$fn = $fn->[0];
#$fn = [ (@{$fn}) ];
#shift @$fn;
				debug("$::level $f after strip fn = \n".Dumper($field)."\n");

				$fieldname = $field->[1]->{fieldname};
				debug("$::level $f processing field: $fieldname\n");
				$args= $field->[1]->{arglist};


# convert the argument list (which could be expressions, other
# variables, etc) into raw values
				if ($args) {
					debug("$::level $f executing $fieldname with args:\n".Dumper($args)."\n");
					($values) = execute($args);
					debug("$::level $f returned values:\n".Dumper($values)."\n");
				}
			}

			debug("$::level $f after execute, \@_=\n".Dumper(\@_)."\n");

#call the function
			if (ref $val) {
				debug("$::level $f : inside loop(before) {\n".Dumper($val)."\n");
				debug("$::level $f : inside loop(before) {\n".Dumper($val)."\n");
				if ($args) {
					debug("$::level $f: function call\n");
#$val = $$val->$fieldname ($args);    # method call
					my $func = $val->{$fieldname};    # method call
					debug("$::level $f: $fieldname func=\n ".Dumper($func)."\n");
					no strict;
					$val = &$func($val, @$values);
					debug("$::level $f: $fieldname result=$val\n");
					debug("$::level $f: $fieldname result=\n".Dumper($val)."\n");

				} else {
					&::debug("$::level $f: plain field access\n");
					if (ref $val eq "REF") {
						$val = $$val->{$fieldname};  # field access
					} else {
						$val = $val->{$fieldname};  # field access
					}
				}
				debug("$::level $f } inside loop(after val retrieval) val=\n".Dumper($val)."\n");
			} 
			$pass++;

		}

		return $val;
	}

	#$return = [ "variablename", \$variableinfo ];
	sub  variablename {
		my $f = "variablename";
		debug("$::level $f: input\n".Dumper(\@_)."\n");
		my $var    = $_[1];
		return $var;
	}

	#arglist:      '(' list(?) ')'
	sub arglist {
		my ($list) = exe_all($_[2]);
		debug("$::level list: ".Dumper($list)."\n");
		if ($list) {
			my $ll = $list->[0];
			debug("$::level ll \n".Dumper($ll)."\n");
			debug("$::level \$\$list: \n");
			return $ll;
		}
		return undef;
	}

    #list:         expression (',' list)(s?)
	sub list {
		my ($expr, $alt) = ( execute($_[1]), $_[2] );

		if (scalar @$alt) {
			my ($list) = exe_optional($alt, 2);

			debug("$::level list: expr: $expr\n");
			debug("$::level list: list: $list\n:");
			debug("$::level list ".Dumper($list)."\n");
			my $r = [ $expr, (@$list) ];
			return $r;
		}
		debug("$::level returning simple expression: $expr\n:");
		return [$expr];
	}

	

	sub _default {
		debug ("$::level default rule {\n");
		indent();
		debug ("$::level parsing parameters\n");
		my @item = exe_all(@_);
		debug ("$::level default rule - last item in array is: ".$item[$#item]."\n");
		my $r = join "",@item[1..$#item];
		debug ("$::level default rule - returning: $r\n");
		deindent();
		debug ("$::level }\n");
		return $r;

	}


}


package Template::Velocity::Executor;

use Data::Dumper;



sub new
{
	my $class = shift;

	my $parsetree = shift;
	my $parser    = shift;

	my $self = {};
	$self->{parser} = $parser;
	$self->{parsetree} = $parsetree;
	bless $self, $class;
	return $self;
}


sub run {
	my $self = shift;

	return (execute($self->{parsetree}));
}



my $level = " ";

sub debug {
	if ($::debugflag) {
		print @_;
	}
}

# This basically all works calling execute($parsetree).
# Execute will look the Parsetree, which is built by a special autoaction
#
# It will call top-down, into functions called 'Executor::XXX', (where XXX is
# the name of the production)
#
# Additional trees, representing child productions, will be passed in
# as arguments to the Executor::XXX function. These arguments be processed
# before the Executor::XXX function can proceed.
#
# If no such function is present, Executor:_default will be run
# 
# To process the arguments, use this in the Executor function:
#     my @item = exe(@_);
# Which will give you an @item array similar to that in the RD rules, one
# exception being that productions which return arrays are flattened into
# the @item array. (bad idea?)
# 



# executes a parsetree (gotten as a result of calling recdescent $parser->rule()
# and returns the string value of the result.

sub Dumper {
 "";
}

sub execute {
		my $result;
		my $tree = shift;   # a reference to a tree is passed in
		debug "$level execute: {\n";	
		indent();
		debug ("$level tree = \n".Dumper($tree)."\n");

# there are 3 possible things this tree could be:

# 1 a scalar .. in which case this rule represents a literal, and the
#              the literal is just returned
#
# 2 an array of the form (array, ...)   - in which case this is the result of a production
#                                         which returned an array of trees. This happens
#                                         if you specify (s), (?), etc, in a production.
# 3 an array of the form (scalar, ...)  - in which case this refers to a subrule
# 

# case 1...
		my $type = ref $tree;
		if ($type) {
			debug "\n$level tree type: ".(ref $tree)." \n";
		} else {
			debug "\n$level tree type: scalar \n";
		}
		if ($type ne "ARRAY") {
			debug "$level   returning literal: '$tree'\n";
			deindent();
			debug "$level }\n\n";
			return $tree;
		}

		my @result;

# if this tree is the result of a auto-generated rule (e.g. alternation)
# then tree[0] is not a name.. it is an array. just call the default action with
# the arguments

		my $rule = @{$tree}->[0];   # rule name is first

		if ($rule && ref $rule eq "ARRAY") {    # case 2
			debug "$level element[0] is an array (case 2) \n";
			debug "$level contents of input: \n".Dumper(\@{$tree})."\n";
			#@result = exe(@{$rule});
			debug "$level running exe on the array..\n";
		# not sure about this...
			@result = (exe_all(@{$tree}));
			debug "$level contents of output: \n".Dumper(\@result)."\n";
			#shift @result;   # get rid of function name
			$result = \@result;
			
		} else {                                # case 3
			my @args = @{$tree};

			debug "$level rule is a function to execute (case 3): '$rule'\n";
			indent();
			my $qr = "Template::Velocity::Executor::Rules::$rule";
			if (defined &$qr) {
				no strict ;
				$result = (&$qr(@args));
			} else {
				debug "$level no function defined for: '$rule' - calling default action\n";
				$result = Template::Velocity::Executor::Rules::_default(@args);
			}
		}
		deindent();
		debug "$level function: $rule returned=\n".Dumper($result)."\n";

		debug "$level }\n";
		return $result;

		}

# these hold and set the current indent level. It's only used for nested debug messages
sub indent {
	if (!$debugflag) { return; }
	$level .= "  ";
	$Data::Dumper::Pad = $level."  ";
}
sub deindent {
	if (!$debugflag) { return; }
	$level = substr ($level,0,-2);
	$Data::Dumper::Pad = $level."  ";
}


sub exe_optional {
	my @r;
	my $f = shift;
	foreach my $q (@_) {
		debug("$level: getting arg# $q\n");
		push @r, execute($f->[0][$q]);
	}
	return @r;
}

# exe: for each argument, run the 'execute' function
#

sub exe_all {
	my $d = $Data::Dumper::Maxdepth;
	$Data::Dumper::Maxdepth = 9;
	debug "\n$level exe_all (".$_[0].") arguments: {\n".Dumper(\@_)." \n";
	my @r;
	indent();

	foreach my $i (@_) {
		push @r, execute($i);
	}
	deindent();
	debug "$level exe_all: returning: \n".Dumper(\@r)."$level}\n\n";
	$Data::Dumper::Maxdepth = $d;
	return @r;
}





#package RHCS::TPS::GlobalVar;

#sub new { my $self = {}; bless $self; return $self; }


1;

