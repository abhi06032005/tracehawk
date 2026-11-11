import { prisma } from '../db.js';
import { startReportChat, stopAllReportChats } from './chat.js';
async function main(){
  const project=await prisma.project.create({data:{name:'Temporary live chat validation',targetUrl:'http://127.0.0.1',allowedOrigins:['http://127.0.0.1']}});
  try{
    const session=await prisma.session.create({data:{projectId:project.id,status:'STOPPED'}});
    const report=await prisma.investigation.create({data:{sessionId:session.id,status:'COMPLETED',maxSteps:20,maxTimeSeconds:0,requestBudget:0,riskSummary:'Synthetic local fixture: the recorded HTML response has no Content-Security-Policy. No injection vulnerability has been demonstrated.'}});
    await startReportChat(report.id,{question:'Explain why missing CSP alone does not prove an exploitable XSS vulnerability, and the next non-destructive verification step.'});
    for(let i=0;i<180;i++){
      const steps=await prisma.investigationStep.findMany({where:{investigationId:report.id},orderBy:{stepNumber:'asc'}});
      const reply=steps.find(s=>s.phase==='CHAT_ASSISTANT'||s.phase==='CHAT_ERROR');
      if(reply){if(reply.phase==='CHAT_ERROR')throw Error(reply.thought);if(steps.length!==2)throw Error('Expected durable question and answer');console.log('Live DeepHat chat passed: question and answer saved and reloaded from PostgreSQL.');return;}
      await new Promise(r=>setTimeout(r,1000));
    }
    throw Error('Live chat validation timed out');
  }finally{stopAllReportChats();await prisma.project.delete({where:{id:project.id}});await prisma.$disconnect();}
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
