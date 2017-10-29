var flag=1;
function f1()
{
    alert("Then you're on your own...Good luck with that!");
}
function f()
{
  if(flag==1)
  {
      Bn.style.top=90;
      Bn.style.left=500;
      flag=2;
  }
  else if(flag==2)
  {
      Bn.style.top=90;
      Bn.style.left=50;
      flag=3;
   }
  else if(flag==3)
  {
      Bn.style.top=235;
      Bn.style.left=360;
      flag=1;
  }
 }

 window.addEventListener('DOMContentLoaded', function(){
   document.getElementById('Iy').addEventListener('click', f1);
   document.getElementById('In').addEventListener('mouseover',f);
 });

