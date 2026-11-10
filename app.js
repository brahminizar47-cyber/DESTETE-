
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// بيانات مشروع DESTATE
const SUPABASE_URL = 'ضع_رابط_مشروعك_هنا';
const SUPABASE_KEY = 'ضع_المفتاح_العام_publishable_هنا';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// إنشاء مكان لعرض نتائج البحث
const searchBox = document.querySelector('.search');

const results = document.createElement('div');
results.id = 'property-results';
results.style.cssText = 'max-width:900px;margin:25px auto;text-align:right;';
searchBox.after(results);

const types = {
  land: 'أرض سكنية',
  agricultural_land: 'أرض فلاحية',
  house: 'دار',
  apartment: 'شقة',
  commercial: 'محل تجاري'
};

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

async function searchProperties() {
  results.innerHTML = '<p>جاري البحث...</p>';

  const type = document.getElementById('type').value;
  const governorate = document.getElementById('governorate').value;
  const maxPrice = document.getElementById('maxPrice').value;

  let query = supabase
    .from('properties')
    .select('id,title,description,property_type,governorate,city,price,area')
    .eq('status', 'published')
    .order('created_at', { ascending: false });

  if (type) query = query.eq('property_type', type);
  if (governorate) query = query.eq('governorate', governorate);
  if (maxPrice) query = query.lte('price', Number(maxPrice));

  const { data, error } = await query;

  if (error) {
    results.innerHTML = '<p>صار خطأ في البحث. حاول مرة أخرى.</p>';
    return;
  }

  if (!data || data.length === 0) {
    results.innerHTML = '<p>ما فماش عقارات منشورة تطابق بحثك حالياً.</p>';
    return;
  }

  results.innerHTML = `
    <h2>نتائج البحث (${data.length})</h2>
    ${data.map(property => `
      <article style="background:white;padding:20px;margin:12px 0;border-radius:12px;border:1px solid #e5e5e5">
        <h3>${escapeHTML(property.title)}</h3>
        <p>${escapeHTML(types[property.property_type] || property.property_type)}</p>
        <p>📍 ${escapeHTML(property.governorate)} ${escapeHTML(property.city || '')}</p>
        <p>💰 ${Number(property.price).toLocaleString('fr-FR')} د.ت</p>
        ${property.area ? `<p>📐 ${escapeHTML(property.area)} م²</p>` : ''}
        <p>${escapeHTML(property.description || '')}</p>
      </article>
    `).join('')}
  `;
}

window.searchProperties = searchProperties;
