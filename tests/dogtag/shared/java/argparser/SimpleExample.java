
/**
 * Gives a very simple example of the use of 
 * {@link argparser.ArgParser ArgParser}.
 */
public class SimpleExample
{
	/**
	 * Run this to invoke command line parsing.
	 */
	public static void main (String[] args) 
	 {
	   // create holder objects for storing results ...
 
	   DoubleHolder theta = new DoubleHolder();
	   StringHolder fileName = new StringHolder();
	   BooleanHolder debug = new BooleanHolder();
 
	   // create the parser and specify the allowed options ...
 
	   ArgParser parser = new ArgParser("java argparser.SimpleExample");
	   parser.addOption ("-theta %f #theta value (in degrees)", theta); 
	   parser.addOption ("-file %s #name of the operating file", fileName);
	   parser.addOption ("-debug %v #enables display of debugging info",
			     debug);

	   // and then match the arguments

	   parser.matchAllArgs (args);

	   // now print out the values

	   System.out.println ("theta=" + theta.value);
	   System.out.println ("fileName=" + fileName.value);
	   System.out.println ("debug=" + debug.value);
	 }
}

