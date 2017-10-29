
function f1()
{
    alert("Then you're on your own...Good luck with that!");
}
function f()
{
  if(flag==1)
  {
      Bn.style.top=90
      Bn.style.left=500
      flag=2
  }
  else if(flag==2)
  {
      Bn.style.top=90
      Bn.style.left=50
      flag=3
   }
  else if(flag==3)
  {
      Bn.style.top=235
      Bn.style.left=360
      flag=1
      }
  }

  document.addEventListener('DOMContentReady', function(){
    document.getElementById('By')
        .addEventListener('click', f1);
        flag=1;
    document.getElementById('Bn')
        .addEventListener('mouseover', f);
  });