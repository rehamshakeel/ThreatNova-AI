import Sidebar from '@/components/Sidebar';
import DashboardHeader from '@/components/DashboardHeader';
import PreferenceInitializer from '@/components/PreferenceInitializer';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-tn-bg">
      <PreferenceInitializer />
      <Sidebar />
      <div className="min-w-0 flex-1">
        <DashboardHeader />
        <main className="mx-auto w-full max-w-[1640px] px-4 pb-10 pt-6 sm:px-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}
