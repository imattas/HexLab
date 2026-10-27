# Plugin panel workflow

The desktop Plugins panel lists registered actions and analysis providers for
loaded modules. Select an action or provider and use its Run button, or
double-click the selected row (Enter activates it as well). Both routes use the
same serialized plugin worker as the corresponding button, so the panel stays
responsive while plugin code runs and reports callback failures in the status
area.

Analysis providers still require a saved project path in the **Project file**
field. The host opens that project read-only for the provider call. Plugin
callbacks execute in-process and are not sandboxed.
