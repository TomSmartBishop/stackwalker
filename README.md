StackWalker
===========

The Stack Walker, walks a callstack for any thread (own, other and remote). It has an abstraction layer, so the calling app does not need to know the internals.

This is a fork of the original repository, currently only VS2015 is maintained due to restructurings
	- Remved almost all memory allocations (using the stack instead, except when retrieving the file version number)
	- Seperated console output from StackWalker, this is now done in the derrived class OutputStackWalker
	- Flags are now working
	- A lot of refactoring to get a cleaner structure
	
bii is not maintained and IMHO obsolete (thinking about conan.io)

PRs welcome, if you find an issue please log it.
    
[StackWalker Original Library](http://stackwalker.codeplex.com/)

[An explanation article @ codeproject](http://www.codeproject.com/Articles/11132/Walking-the-callstack)
