# BackdoorCTF 2021
pwn, 500.

I didn't manage to solve this challenge during the ctf , but i kept trying until i finished it so this is a little writeup so i can share what i learnt and for keeping it as a resource for me for next challs.
## Description
> A classic heap exploitation challenge but with a plot twist.

# Analysis
let's start by reversing the four main functions.
**All reversing was made in IDA PRO 7.5**
#### Create Function
```C
unsigned __int64 main_allocate()
{
  unsigned int number_of_chunks; // [rsp+Ch] [rbp-14h] BYREF
  unsigned int choice; // [rsp+10h] [rbp-10h] BYREF
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("How many chunks do you wanna allocate: ");
  number_of_chunks = 0;
  __isoc99_scanf("%u", &number_of_chunks);
  puts("Select the size: ");
  men_for_chunk_sizes();
  choice = 0;
  __isoc99_scanf("%d", &choice);
  for ( i = 0; i < number_of_chunks; ++i )
  {
    TODO();
    counter2_and_allocation(choice);
  }
  return __readfsqword(0x28u) ^ v4;
}
```
We are Prompted to enter the number of chunks we want to allocate. Then we chose the size we want from a menu.
```C
int men_for_chunk_sizes()
{
  puts("1. Large size.");
  puts("2. Medium size.");
  puts("3. Small size.");
  return printf(">> ");
}
```
Then we enter a loop which loops depending on how many chunks we are going to allocate
If we focus a little bit in here we can notice a strange thing happening which is we have 2 counters incrementing, We will figure out why later on.
 **counter2_and_allocation()**
```C
void __fastcall counter2_and_allocation(int a1)
{
  unsigned int index; // ebx
  int size; // [rsp+1Ch] [rbp-14h]

  if ( a1 == 3 )                                // small
  {
    size = 128;
  }
  else
  {
    if ( a1 > 3 )
      return;
    if ( a1 == 1 )                              // large
    {
      size = 1040;
    }
    else
    {
      if ( a1 != 2 )                            // medium
        return;
      size = 512;
    }
  }
  if ( (unsigned int)index_counter > 16 )       // MAX OF 16 ALLOCATIONS
    exit(0);
  index = index_counter++;
  notes[index] = malloc(size);
}
```
 **TODO()**
```C
__int64 TODO()
{
  return (unsigned int)++COUNTER_FROM_TODO;
}
```
