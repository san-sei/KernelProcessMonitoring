#include <wdm.h>

#define max_thread_count 20

int myThreadExArray[max_thread_count];
int myProcessExArray[max_thread_count];
int mycurrentIndex = -1;

int additem(int threadId, int processId)
{
	if (mycurrentIndex < max_thread_count - 1)
		return -1;
	mycurrentIndex++;
	myThreadExArray[mycurrentIndex] = threadId;
	myProcessExArray[mycurrentIndex] = processId;
	return 1;
}

int finditem(int threadId)
{
	for (int i = 0; i <= mycurrentIndex; i++)
	{
		if (myThreadExArray[i] == threadId)
			return myProcessExArray[i];
	}
	return -1;
}
