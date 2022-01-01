#BackdoorCTF 2021
pwn, 500.


##Description
> A classic heap exploitation challenge but with a plot twist.
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
