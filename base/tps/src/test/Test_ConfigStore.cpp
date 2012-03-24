// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---


#include "main/ConfigStore.h"


// This is needed to resolve a symbol expected by the linker
int __nsapi30_table;

ConfigStore getsubstore(ConfigStore& config, char *subname)
{
	printf("Getting sub store : %s\n", subname);
	ConfigStore sub2 = config.GetSubStore(subname);
	const char *t = sub2.GetConfigAsString("string");
	printf("substore string   : %s\n", t);


	printf("returning substore to parent\n");
	return sub2;
}

int main()
{
	int i;
	const char *s;

	ConfigStore *cfg = ConfigStore::CreateFromConfigFile("Test_ConfigStore.cfg");
	
	printf("TOP LEVEL\n");
	i = cfg->GetConfigAsInt("integer");
	printf("int    : %d\n",i);
	s = cfg->GetConfigAsString("string");
	printf("string : %s\n",s);


	printf("\nSUB1 LEVEL\n");
	ConfigStore subcfg = cfg->GetSubStore("sub1");
	i = subcfg.GetConfigAsInt("integer");
	printf("int      : %d\n",i);
	s = subcfg.GetConfigAsString("string");
	printf("string   : %s\n",s);
	s = subcfg["string"];
	printf("[string] : %s\n",s);

	printf("\nSUB2 LEVEL in method\n");
	ConfigStore sub2cfg = getsubstore(subcfg,"sub2");
	printf("accessing sub2 from main\n");
	i = sub2cfg.GetConfigAsInt("integer");
	printf("int      : %d\n",i);
	
	
	printf("\nTOP LEVEL AGAIN\n");
	i = cfg->GetConfigAsInt("integer");
	printf("int      : %d\n",i);
	s = cfg->GetConfigAsString("string");

	ConfigStore subcfg2 = cfg->GetSubStore("level2");


}

